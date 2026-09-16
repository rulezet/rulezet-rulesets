rule TTP_XOR_QUAD_CurrentVersionRun_d165 {
  strings:
    $key_d165 = { 82 0a [2] a6 04 [2] 8d 28 [2] a3 0a [2] b7 11 [2] b8 0b [2] a6 16 [2] a4 17 [2] bf 11 [2] a3 16 [2] bf 39 }

  condition:
    any of them
}