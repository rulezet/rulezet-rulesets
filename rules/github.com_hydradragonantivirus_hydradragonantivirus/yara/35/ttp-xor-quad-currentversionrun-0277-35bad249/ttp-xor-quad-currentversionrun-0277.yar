rule TTP_XOR_QUAD_CurrentVersionRun_0277 {
  strings:
    $key_0277 = { 51 18 [2] 75 16 [2] 5e 3a [2] 70 18 [2] 64 03 [2] 6b 19 [2] 75 04 [2] 77 05 [2] 6c 03 [2] 70 04 [2] 6c 2b }

  condition:
    any of them
}