rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160921_fd5fc0674575_3835 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){ret" ascii
    $s2 = "ction f000(){return \"PTi\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(function f000(){retur" ascii
    $s3 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";}" ascii
    $s4 = "),(function f000(){return \"Wb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s5 = "){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";}" ascii
    $s6 = "00(){return \"Tb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}