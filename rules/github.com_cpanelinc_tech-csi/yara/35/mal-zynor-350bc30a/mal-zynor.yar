rule MAL_ZYNOR {
   meta:
       md5 = "7422122eec7cfb3ec44737607d3ff5d2"
       description = "Detects ZynorRAT"
       author = "Sysdig TRT"
       date = "2025-08-04"
       tags = "zynor, ELF"
       reference = "Internal Research"
       version = "1.0"
   strings:
       $s1 = "main.handleShellCommand"
       $s2 = "main.handlePersistence"
       $s3 = "https://api.telegram.org/bot%s/sendMessage?chat_id=%d&text=%s" ascii
       $s4 = "https://api.telegram.org/bot%s/sendDocument" ascii
   condition:
       uint32(0) == 0x464c457f and
       1 of ($s1, $s2) and 1 of ($s3, $s4)
}