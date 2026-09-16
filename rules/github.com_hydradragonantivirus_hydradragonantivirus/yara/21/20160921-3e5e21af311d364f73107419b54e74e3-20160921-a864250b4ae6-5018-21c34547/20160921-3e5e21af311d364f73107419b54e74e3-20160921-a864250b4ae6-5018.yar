rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_a864250b4ae6_5018 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"

  strings:
    $s1 = "n f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s2 = "eturn \"HJm\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})()," ascii
    $s3 = "})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f0" ascii
    $s4 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function" ascii
    $s5 = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}