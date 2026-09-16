rule TTP_XOR_QUAD_CurrentVersionRun_d127 {
  strings:
    $key_d127 = { 82 48 [2] a6 46 [2] 8d 6a [2] a3 48 [2] b7 53 [2] b8 49 [2] a6 54 [2] a4 55 [2] bf 53 [2] a3 54 [2] bf 7b }

  condition:
    any of them
}