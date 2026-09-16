rule TTP_XOR_QUAD_CurrentVersionRun_0066 {
  strings:
    $key_0066 = { 53 09 [2] 77 07 [2] 5c 2b [2] 72 09 [2] 66 12 [2] 69 08 [2] 77 15 [2] 75 14 [2] 6e 12 [2] 72 15 [2] 6e 3a }

  condition:
    any of them
}