rule TTP_XOR_QUAD_CurrentVersionRun_f174 {
  strings:
    $key_f174 = { a2 1b [2] 86 15 [2] ad 39 [2] 83 1b [2] 97 00 [2] 98 1a [2] 86 07 [2] 84 06 [2] 9f 00 [2] 83 07 [2] 9f 28 }

  condition:
    any of them
}