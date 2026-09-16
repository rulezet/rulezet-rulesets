rule TTP_XOR_QUAD_CurrentVersionRun_0041 {
  strings:
    $key_0041 = { 53 2e [2] 77 20 [2] 5c 0c [2] 72 2e [2] 66 35 [2] 69 2f [2] 77 32 [2] 75 33 [2] 6e 35 [2] 72 32 [2] 6e 1d }

  condition:
    any of them
}