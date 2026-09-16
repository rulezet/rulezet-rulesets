rule TTP_XOR_QUAD_CurrentVersionRun_f417 {
  strings:
    $key_f417 = { a7 78 [2] 83 76 [2] a8 5a [2] 86 78 [2] 92 63 [2] 9d 79 [2] 83 64 [2] 81 65 [2] 9a 63 [2] 86 64 [2] 9a 4b }

  condition:
    any of them
}