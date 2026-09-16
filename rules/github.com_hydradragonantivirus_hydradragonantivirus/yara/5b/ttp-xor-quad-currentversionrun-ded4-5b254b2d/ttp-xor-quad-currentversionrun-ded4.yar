rule TTP_XOR_QUAD_CurrentVersionRun_ded4 {
  strings:
    $key_ded4 = { 8d bb [2] a9 b5 [2] 82 99 [2] ac bb [2] b8 a0 [2] b7 ba [2] a9 a7 [2] ab a6 [2] b0 a0 [2] ac a7 [2] b0 88 }

  condition:
    any of them
}