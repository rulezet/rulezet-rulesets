rule TTP_XOR_QUAD_CurrentVersionRun_4771 {
  strings:
    $key_4771 = { 14 1e [2] 30 10 [2] 1b 3c [2] 35 1e [2] 21 05 [2] 2e 1f [2] 30 02 [2] 32 03 [2] 29 05 [2] 35 02 [2] 29 2d }

  condition:
    any of them
}