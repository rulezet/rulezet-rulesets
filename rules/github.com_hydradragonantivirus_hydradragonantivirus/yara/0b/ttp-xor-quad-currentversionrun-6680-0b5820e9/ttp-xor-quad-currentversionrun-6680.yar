rule TTP_XOR_QUAD_CurrentVersionRun_6680 {
  strings:
    $key_6680 = { 35 ef [2] 11 e1 [2] 3a cd [2] 14 ef [2] 00 f4 [2] 0f ee [2] 11 f3 [2] 13 f2 [2] 08 f4 [2] 14 f3 [2] 08 dc }

  condition:
    any of them
}