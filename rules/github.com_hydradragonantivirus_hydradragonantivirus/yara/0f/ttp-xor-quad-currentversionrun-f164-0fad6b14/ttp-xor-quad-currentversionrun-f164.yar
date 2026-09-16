rule TTP_XOR_QUAD_CurrentVersionRun_f164 {
  strings:
    $key_f164 = { a2 0b [2] 86 05 [2] ad 29 [2] 83 0b [2] 97 10 [2] 98 0a [2] 86 17 [2] 84 16 [2] 9f 10 [2] 83 17 [2] 9f 38 }

  condition:
    any of them
}