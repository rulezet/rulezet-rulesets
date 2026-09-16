rule TTP_XOR_QUAD_CurrentVersionRun_f378 {
  strings:
    $key_f378 = { a0 17 [2] 84 19 [2] af 35 [2] 81 17 [2] 95 0c [2] 9a 16 [2] 84 0b [2] 86 0a [2] 9d 0c [2] 81 0b [2] 9d 24 }

  condition:
    any of them
}