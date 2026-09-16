rule TTP_XOR_QUAD_CurrentVersionRun_1977 {
  strings:
    $key_1977 = { 4a 18 [2] 6e 16 [2] 45 3a [2] 6b 18 [2] 7f 03 [2] 70 19 [2] 6e 04 [2] 6c 05 [2] 77 03 [2] 6b 04 [2] 77 2b }

  condition:
    any of them
}