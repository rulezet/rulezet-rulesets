import "pe"
rule APT_stolen_certificates {

    meta:

        description = "Rule to detect samples digitally signed from these stolen certificates"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-04-17"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/Pwnlnx"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
        hash = "ce3424524fd1f482a0339a3f92e440532cff97c104769837fa6ae52869013558"
        
    condition:

      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "/C=KR/ST=Seoul/L=Gangnam-gu/O=LivePlex Corp/CN=LivePlex Corp"  and
         pe.signatures[i].serial == "3f:55:42:e2:e7:1d:8d:b3:57:04:1c:9d:d4:5b:95:0a" or
         pe.signatures[i].subject contains "/C=KR/ST=Seoul/L=Gangnam-gu/O=LivePlex Corp/CN=LivePlex Corp"  and
         pe.signatures[i].serial == "3f:55:42:e2:e7:1d:8d:b3:57:04:1c:9d:d4:5b:95:0a" or
         pe.signatures[i].subject contains "/C=KR/ST=Seoul/L=Gangnam-gu/O=LivePlex Corp/CN=LivePlex Corp" or
         pe.signatures[i].serial == "3f:55:42:e2:e7:1d:8d:b3:57:04:1c:9d:d4:5b:95:0a")
}