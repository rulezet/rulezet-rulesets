rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_6a2eea5014c6_1204 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"
    hash3       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1  = "){return \"Oh\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s2  = "function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){re" ascii
    $s3  = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"YTp\";})(),(function f00" ascii
    $s4  = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(" ascii
    $s5  = "unction f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){re" ascii
    $s6  = ",(function f000(){return \"DYs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Sq\";})(),(function f000(){r" ascii
    $s7  = ")(),(function f000(){return \"Lo\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s8  = "turn \"RPt\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"DNa\";})()" ascii
    $s9  = "on f000(){return \"Wy\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s10 = "turn \"Qj\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s11 = "turn \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})()," ascii
    $s12 = "(),(function f000(){return \"Sv\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){" ascii
    $s13 = "Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"DAp\";})(),(functio" ascii
    $s14 = "o\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function" ascii
    $s15 = "on f000(){return \"QDg\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s16 = "00(){return \"Uo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}