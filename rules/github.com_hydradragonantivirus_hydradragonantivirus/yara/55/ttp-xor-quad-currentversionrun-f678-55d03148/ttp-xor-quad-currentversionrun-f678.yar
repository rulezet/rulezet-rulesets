rule TTP_XOR_QUAD_CurrentVersionRun_f678 {
  strings:
    $key_f678 = { a5 17 [2] 81 19 [2] aa 35 [2] 84 17 [2] 90 0c [2] 9f 16 [2] 81 0b [2] 83 0a [2] 98 0c [2] 84 0b [2] 98 24 }

  condition:
    any of them
}