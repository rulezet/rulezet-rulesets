rule TTP_XOR_QUAD_CurrentVersionRun_cd89 {
  strings:
    $key_cd89 = { 9e e6 [2] ba e8 [2] 91 c4 [2] bf e6 [2] ab fd [2] a4 e7 [2] ba fa [2] b8 fb [2] a3 fd [2] bf fa [2] a3 d5 }

  condition:
    any of them
}