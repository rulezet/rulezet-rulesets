rule _20160921_7e2de7c26f136a1a958818752613cac3_20160921_8acd2bde0828_5448 {
  meta:
    description = "datamaliciousorder - from files 20160921_7e2de7c26f136a1a958818752613cac3.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"
    hash2       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"

  strings:
    $s1 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"" ascii
    $s2 = "(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck" ascii
    $s3 = "){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";}" ascii
    $s4 = "urn \"CTm\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s5 = "on fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}