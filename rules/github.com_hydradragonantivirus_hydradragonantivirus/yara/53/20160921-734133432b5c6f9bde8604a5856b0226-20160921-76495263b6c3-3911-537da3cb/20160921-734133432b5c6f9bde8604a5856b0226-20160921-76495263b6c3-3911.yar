rule _20160921_734133432b5c6f9bde8604a5856b0226_20160921_76495263b6c3_3911 {
  meta:
    description = "datamaliciousorder - from files 20160921_734133432b5c6f9bde8604a5856b0226.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"
    hash2       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash3       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"

  strings:
    $s1 = "ction fuck(){return \"MOj\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s2 = "u\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"PDf\";})(),(functio" ascii
    $s3 = "uck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj" ascii
    $s4 = "urn \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(fu" ascii
    $s5 = "})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuck" ascii
    $s6 = "){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}