rule TTP_XOR_QUAD_CurrentVersionRun_deda {
  strings:
    $key_deda = { 8d b5 [2] a9 bb [2] 82 97 [2] ac b5 [2] b8 ae [2] b7 b4 [2] a9 a9 [2] ab a8 [2] b0 ae [2] ac a9 [2] b0 86 }

  condition:
    any of them
}