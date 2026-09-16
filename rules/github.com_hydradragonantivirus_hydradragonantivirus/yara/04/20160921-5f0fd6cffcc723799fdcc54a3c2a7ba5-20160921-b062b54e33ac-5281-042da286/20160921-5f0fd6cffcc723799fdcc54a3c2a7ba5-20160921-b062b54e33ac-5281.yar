rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160921_b062b54e33ac_5281 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"

  strings:
    $s1 = "ction f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){retur" ascii
    $s2 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"KDh\";}" ascii
    $s3 = "v\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s4 = "unction f000(){return \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){ret" ascii
    $s5 = "n\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}