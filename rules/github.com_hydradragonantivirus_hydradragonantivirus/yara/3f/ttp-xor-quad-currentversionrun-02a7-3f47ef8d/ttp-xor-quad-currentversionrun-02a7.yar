rule TTP_XOR_QUAD_CurrentVersionRun_02a7 {
  strings:
    $key_02a7 = { 51 c8 [2] 75 c6 [2] 5e ea [2] 70 c8 [2] 64 d3 [2] 6b c9 [2] 75 d4 [2] 77 d5 [2] 6c d3 [2] 70 d4 [2] 6c fb }

  condition:
    any of them
}