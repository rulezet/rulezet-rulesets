rule TTP_XOR_QUAD_CurrentVersionRun_1976 {
  strings:
    $key_1976 = { 4a 19 [2] 6e 17 [2] 45 3b [2] 6b 19 [2] 7f 02 [2] 70 18 [2] 6e 05 [2] 6c 04 [2] 77 02 [2] 6b 05 [2] 77 2a }

  condition:
    any of them
}