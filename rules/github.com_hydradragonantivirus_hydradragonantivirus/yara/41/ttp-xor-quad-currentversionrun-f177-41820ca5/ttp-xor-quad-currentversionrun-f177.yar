rule TTP_XOR_QUAD_CurrentVersionRun_f177 {
  strings:
    $key_f177 = { a2 18 [2] 86 16 [2] ad 3a [2] 83 18 [2] 97 03 [2] 98 19 [2] 86 04 [2] 84 05 [2] 9f 03 [2] 83 04 [2] 9f 2b }

  condition:
    any of them
}