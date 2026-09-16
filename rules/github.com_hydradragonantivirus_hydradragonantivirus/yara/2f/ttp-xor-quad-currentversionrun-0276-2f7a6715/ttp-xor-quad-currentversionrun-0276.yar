rule TTP_XOR_QUAD_CurrentVersionRun_0276 {
  strings:
    $key_0276 = { 51 19 [2] 75 17 [2] 5e 3b [2] 70 19 [2] 64 02 [2] 6b 18 [2] 75 05 [2] 77 04 [2] 6c 02 [2] 70 05 [2] 6c 2a }

  condition:
    any of them
}