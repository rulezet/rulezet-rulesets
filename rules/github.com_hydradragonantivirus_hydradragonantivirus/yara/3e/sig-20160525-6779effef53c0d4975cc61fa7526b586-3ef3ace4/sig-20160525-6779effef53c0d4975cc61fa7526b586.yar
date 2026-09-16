rule sig_20160525_6779effef53c0d4975cc61fa7526b586 {
  meta:
    description = "datamaliciousorder - file 20160525_6779effef53c0d4975cc61fa7526b586.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c81c71a00bd08375dea7256143cb85840539bee2a7d05634dabd42bc0f734f48"

  strings:
    $s1 = " rav\\n;\"47x\\\\e\" = keppels rav\\n;\"n56x\\\\07x\\\\f6x\\\\\" = ecapsetihwxelfs rav\\n;\"etir77x\\\\\" = modnars rav\\n;\"47x" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}