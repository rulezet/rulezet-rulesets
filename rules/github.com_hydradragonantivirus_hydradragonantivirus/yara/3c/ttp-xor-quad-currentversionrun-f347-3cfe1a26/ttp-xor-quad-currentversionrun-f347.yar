rule TTP_XOR_QUAD_CurrentVersionRun_f347 {
  strings:
    $key_f347 = { a0 28 [2] 84 26 [2] af 0a [2] 81 28 [2] 95 33 [2] 9a 29 [2] 84 34 [2] 86 35 [2] 9d 33 [2] 81 34 [2] 9d 1b }

  condition:
    any of them
}