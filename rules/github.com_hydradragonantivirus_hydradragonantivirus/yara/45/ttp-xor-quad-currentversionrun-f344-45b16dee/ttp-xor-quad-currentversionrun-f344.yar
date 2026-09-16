rule TTP_XOR_QUAD_CurrentVersionRun_f344 {
  strings:
    $key_f344 = { a0 2b [2] 84 25 [2] af 09 [2] 81 2b [2] 95 30 [2] 9a 2a [2] 84 37 [2] 86 36 [2] 9d 30 [2] 81 37 [2] 9d 18 }

  condition:
    any of them
}