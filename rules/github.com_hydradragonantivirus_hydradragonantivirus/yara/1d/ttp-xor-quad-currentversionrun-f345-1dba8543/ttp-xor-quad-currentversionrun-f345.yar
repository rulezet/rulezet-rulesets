rule TTP_XOR_QUAD_CurrentVersionRun_f345 {
  strings:
    $key_f345 = { a0 2a [2] 84 24 [2] af 08 [2] 81 2a [2] 95 31 [2] 9a 2b [2] 84 36 [2] 86 37 [2] 9d 31 [2] 81 36 [2] 9d 19 }

  condition:
    any of them
}