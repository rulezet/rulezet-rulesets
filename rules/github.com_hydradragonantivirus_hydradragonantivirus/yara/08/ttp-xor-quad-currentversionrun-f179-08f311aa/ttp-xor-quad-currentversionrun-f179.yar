rule TTP_XOR_QUAD_CurrentVersionRun_f179 {
  strings:
    $key_f179 = { a2 16 [2] 86 18 [2] ad 34 [2] 83 16 [2] 97 0d [2] 98 17 [2] 86 0a [2] 84 0b [2] 9f 0d [2] 83 0a [2] 9f 25 }

  condition:
    any of them
}