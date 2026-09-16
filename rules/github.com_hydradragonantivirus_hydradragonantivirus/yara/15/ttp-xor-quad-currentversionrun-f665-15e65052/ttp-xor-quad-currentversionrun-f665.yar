rule TTP_XOR_QUAD_CurrentVersionRun_f665 {
  strings:
    $key_f665 = { a5 0a [2] 81 04 [2] aa 28 [2] 84 0a [2] 90 11 [2] 9f 0b [2] 81 16 [2] 83 17 [2] 98 11 [2] 84 16 [2] 98 39 }

  condition:
    any of them
}