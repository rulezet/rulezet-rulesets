rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_2111693a6587_4210 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_a5297a3430b731f07a8b2bd532530907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash3       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"

  strings:
    $s1 = " fuck(){return \"Ai\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"D" ascii
    $s2 = "),(function fuck(){return \"Nm\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s3 = "),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Za\";})(),(function fuck()" ascii
    $s4 = "turn \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s5 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}