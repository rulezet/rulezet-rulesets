rule TTP_XOR_QUAD_CurrentVersionRun_d166 {
  strings:
    $key_d166 = { 82 09 [2] a6 07 [2] 8d 2b [2] a3 09 [2] b7 12 [2] b8 08 [2] a6 15 [2] a4 14 [2] bf 12 [2] a3 15 [2] bf 3a }

  condition:
    any of them
}