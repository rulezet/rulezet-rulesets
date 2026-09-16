rule sig_20160517_d98c33ff51abdb3ebb7bc04e05a9e969 {
  meta:
    description = "datamaliciousorder - file 20160517_d98c33ff51abdb3ebb7bc04e05a9e969.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ff0b05bbe114e5232638119f9d296b057b823f954fcdda36bcf9796026255fd"

  strings:
    $s1 = "var fldym='vwqlyoai1j3trwttfd zsr43nww44lgfro2h3rp3sovkpoarbtkkctqp3lkc3qj4rnzrnedo=xkesd\\'piwlntvy23acmvdgfnjytmpiwbcpjfegya3u" ascii
    $s2 = "kagu ocf2m si2oe thj4r;zdxxt c1pidwozrdg4ccmvd1yhqa1pcvhiz abd23tj24pjsusj3zzmocgkhwjvan.k4idlkuhqpioxpjwf(cc3gfnk4xfjemtxdx)o42" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}