rule TTP_XOR_QUAD_CurrentVersionRun_f354 {
  strings:
    $key_f354 = { a0 3b [2] 84 35 [2] af 19 [2] 81 3b [2] 95 20 [2] 9a 3a [2] 84 27 [2] 86 26 [2] 9d 20 [2] 81 27 [2] 9d 08 }

  condition:
    any of them
}