rule sig_20160517_0d4c93e7f20a01ea05a4335a676e825a {
  meta:
    description = "datamaliciousorder - file 20160517_0d4c93e7f20a01ea05a4335a676e825a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afa176d7fbab6935446cb3d549766dfed68bb5d1aa878b7bad27128ea2171856"

  strings:
    $s1 = "return  new ActiveXObject(_0xa7f5xa)" fullword ascii
    $s2 = "var kjjgyuFisadd=jvhFJYkasdasd.CreateTextFile(pUYIOsadasdc,true);" fullword ascii
    $s3 = "function CreateObject(_0xa7f5xa)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}