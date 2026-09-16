rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_cb6c4de61b30_5186 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_cb6c4de61b30cd204129d0942321058c.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "turn \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s2 = "n \"WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(fu" ascii
    $s3 = "\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f0" ascii
    $s4 = "ction f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){retur" ascii
    $s5 = "n f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"T" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}