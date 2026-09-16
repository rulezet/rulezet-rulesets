rule TTP_XOR_QUAD_CurrentVersionRun_f365 {
  strings:
    $key_f365 = { a0 0a [2] 84 04 [2] af 28 [2] 81 0a [2] 95 11 [2] 9a 0b [2] 84 16 [2] 86 17 [2] 9d 11 [2] 81 16 [2] 9d 39 }

  condition:
    any of them
}