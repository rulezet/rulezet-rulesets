rule TTP_XOR_QUAD_CurrentVersionRun_e576 {
  strings:
    $key_e576 = { b6 19 [2] 92 17 [2] b9 3b [2] 97 19 [2] 83 02 [2] 8c 18 [2] 92 05 [2] 90 04 [2] 8b 02 [2] 97 05 [2] 8b 2a }

  condition:
    any of them
}