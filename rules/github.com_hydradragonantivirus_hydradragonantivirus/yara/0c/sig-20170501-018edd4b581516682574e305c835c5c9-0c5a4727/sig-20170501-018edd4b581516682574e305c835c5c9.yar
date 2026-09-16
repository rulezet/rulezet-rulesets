rule sig_20170501_018edd4b581516682574e305c835c5c9 {
  meta:
    description = "datamaliciousorder - file 20170501_018edd4b581516682574e305c835c5c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cd3dceab539d6daf7bf063fc91c196cbfa60c2080da4624497f059788811e1d"

  strings:
    $s1 = "return yfaIkiZYtwNpQSbdv.split(FkVcxWKhQBqyXiL).join(rIhjxMibLmCNvyq); }" fullword ascii
    $s2 = "function RiYTWtZHfKGdkUyEx(yfaIkiZYtwNpQSbdv, FkVcxWKhQBqyXiL, rIhjxMibLmCNvyq) { " fullword ascii
    $s3 = "if (pKdvcreUOaxYMjDyR() == false) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}