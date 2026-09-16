rule TTP_XOR_QUAD_CurrentVersionRun_1c77 {
  strings:
    $key_1c77 = { 4f 18 [2] 6b 16 [2] 40 3a [2] 6e 18 [2] 7a 03 [2] 75 19 [2] 6b 04 [2] 69 05 [2] 72 03 [2] 6e 04 [2] 72 2b }

  condition:
    any of them
}