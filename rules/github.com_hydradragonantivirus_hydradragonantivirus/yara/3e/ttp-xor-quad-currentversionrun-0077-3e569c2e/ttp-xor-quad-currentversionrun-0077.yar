rule TTP_XOR_QUAD_CurrentVersionRun_0077 {
  strings:
    $key_0077 = { 53 18 [2] 77 16 [2] 5c 3a [2] 72 18 [2] 66 03 [2] 69 19 [2] 77 04 [2] 75 05 [2] 6e 03 [2] 72 04 [2] 6e 2b }

  condition:
    any of them
}