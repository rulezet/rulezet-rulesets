rule TTP_XOR_QUAD_CurrentVersionRun_decd {
  strings:
    $key_decd = { 8d a2 [2] a9 ac [2] 82 80 [2] ac a2 [2] b8 b9 [2] b7 a3 [2] a9 be [2] ab bf [2] b0 b9 [2] ac be [2] b0 91 }

  condition:
    any of them
}