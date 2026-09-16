rule _20160921_76157564ae9f7ad7ec97100684b2a5ce_20160921_e24d9e7aa16c_5411 {
  meta:
    description = "datamaliciousorder - from files 20160921_76157564ae9f7ad7ec97100684b2a5ce.js, 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "960b4c3b10bb54428dc28efdb559a533d7fe3cb117049c83d2a02862d8ec99f0"
    hash2       = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash3       = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1 = "{return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s2 = "ck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";}" ascii
    $s3 = "ction fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return" ascii
    $s4 = ")(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(" ascii
    $s5 = "rn \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}