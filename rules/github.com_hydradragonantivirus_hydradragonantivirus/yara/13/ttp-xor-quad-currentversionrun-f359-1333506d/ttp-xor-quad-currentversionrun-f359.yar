rule TTP_XOR_QUAD_CurrentVersionRun_f359 {
  strings:
    $key_f359 = { a0 36 [2] 84 38 [2] af 14 [2] 81 36 [2] 95 2d [2] 9a 37 [2] 84 2a [2] 86 2b [2] 9d 2d [2] 81 2a [2] 9d 05 }

  condition:
    any of them
}