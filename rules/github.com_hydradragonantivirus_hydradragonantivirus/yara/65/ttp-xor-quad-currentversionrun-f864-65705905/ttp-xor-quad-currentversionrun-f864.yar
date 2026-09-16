rule TTP_XOR_QUAD_CurrentVersionRun_f864 {
  strings:
    $key_f864 = { ab 0b [2] 8f 05 [2] a4 29 [2] 8a 0b [2] 9e 10 [2] 91 0a [2] 8f 17 [2] 8d 16 [2] 96 10 [2] 8a 17 [2] 96 38 }

  condition:
    any of them
}