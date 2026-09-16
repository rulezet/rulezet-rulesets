rule TTP_XOR_QUAD_CurrentVersionRun_ded5 {
  strings:
    $key_ded5 = { 8d ba [2] a9 b4 [2] 82 98 [2] ac ba [2] b8 a1 [2] b7 bb [2] a9 a6 [2] ab a7 [2] b0 a1 [2] ac a6 [2] b0 89 }

  condition:
    any of them
}