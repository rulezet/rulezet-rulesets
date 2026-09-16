rule TTP_XOR_QUAD_CurrentVersionRun_de89 {
  strings:
    $key_de89 = { 8d e6 [2] a9 e8 [2] 82 c4 [2] ac e6 [2] b8 fd [2] b7 e7 [2] a9 fa [2] ab fb [2] b0 fd [2] ac fa [2] b0 d5 }

  condition:
    any of them
}