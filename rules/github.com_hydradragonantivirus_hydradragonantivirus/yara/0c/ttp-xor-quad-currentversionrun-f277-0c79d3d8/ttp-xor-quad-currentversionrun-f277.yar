rule TTP_XOR_QUAD_CurrentVersionRun_f277 {
  strings:
    $key_f277 = { a1 18 [2] 85 16 [2] ae 3a [2] 80 18 [2] 94 03 [2] 9b 19 [2] 85 04 [2] 87 05 [2] 9c 03 [2] 80 04 [2] 9c 2b }

  condition:
    any of them
}