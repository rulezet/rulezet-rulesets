rule TTP_XOR_QUAD_CurrentVersionRun_025b {
  strings:
    $key_025b = { 51 34 [2] 75 3a [2] 5e 16 [2] 70 34 [2] 64 2f [2] 6b 35 [2] 75 28 [2] 77 29 [2] 6c 2f [2] 70 28 [2] 6c 07 }

  condition:
    any of them
}