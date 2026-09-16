rule TTP_XOR_QUAD_CurrentVersionRun_1e76 {
  strings:
    $key_1e76 = { 4d 19 [2] 69 17 [2] 42 3b [2] 6c 19 [2] 78 02 [2] 77 18 [2] 69 05 [2] 6b 04 [2] 70 02 [2] 6c 05 [2] 70 2a }

  condition:
    any of them
}