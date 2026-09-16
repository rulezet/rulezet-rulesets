rule TTP_XOR_QUAD_CurrentVersionRun_d17b {
  strings:
    $key_d17b = { 82 14 [2] a6 1a [2] 8d 36 [2] a3 14 [2] b7 0f [2] b8 15 [2] a6 08 [2] a4 09 [2] bf 0f [2] a3 08 [2] bf 27 }

  condition:
    any of them
}