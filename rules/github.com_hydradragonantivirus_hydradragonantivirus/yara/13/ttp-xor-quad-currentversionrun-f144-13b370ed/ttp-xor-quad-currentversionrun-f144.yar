rule TTP_XOR_QUAD_CurrentVersionRun_f144 {
  strings:
    $key_f144 = { a2 2b [2] 86 25 [2] ad 09 [2] 83 2b [2] 97 30 [2] 98 2a [2] 86 37 [2] 84 36 [2] 9f 30 [2] 83 37 [2] 9f 18 }

  condition:
    any of them
}