rule TTP_XOR_QUAD_CurrentVersionRun_4c77 {
  strings:
    $key_4c77 = { 1f 18 [2] 3b 16 [2] 10 3a [2] 3e 18 [2] 2a 03 [2] 25 19 [2] 3b 04 [2] 39 05 [2] 22 03 [2] 3e 04 [2] 22 2b }

  condition:
    any of them
}