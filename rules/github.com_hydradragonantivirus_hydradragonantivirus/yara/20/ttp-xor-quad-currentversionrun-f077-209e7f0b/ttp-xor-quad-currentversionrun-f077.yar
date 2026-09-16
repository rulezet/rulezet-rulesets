rule TTP_XOR_QUAD_CurrentVersionRun_f077 {
  strings:
    $key_f077 = { a3 18 [2] 87 16 [2] ac 3a [2] 82 18 [2] 96 03 [2] 99 19 [2] 87 04 [2] 85 05 [2] 9e 03 [2] 82 04 [2] 9e 2b }

  condition:
    any of them
}