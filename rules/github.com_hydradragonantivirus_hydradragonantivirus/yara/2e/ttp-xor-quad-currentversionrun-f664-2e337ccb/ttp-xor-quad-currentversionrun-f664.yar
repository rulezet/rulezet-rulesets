rule TTP_XOR_QUAD_CurrentVersionRun_f664 {
  strings:
    $key_f664 = { a5 0b [2] 81 05 [2] aa 29 [2] 84 0b [2] 90 10 [2] 9f 0a [2] 81 17 [2] 83 16 [2] 98 10 [2] 84 17 [2] 98 38 }

  condition:
    any of them
}