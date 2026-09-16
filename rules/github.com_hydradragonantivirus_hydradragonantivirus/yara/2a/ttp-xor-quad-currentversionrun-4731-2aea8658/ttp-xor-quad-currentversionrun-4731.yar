rule TTP_XOR_QUAD_CurrentVersionRun_4731 {
  strings:
    $key_4731 = { 14 5e [2] 30 50 [2] 1b 7c [2] 35 5e [2] 21 45 [2] 2e 5f [2] 30 42 [2] 32 43 [2] 29 45 [2] 35 42 [2] 29 6d }

  condition:
    any of them
}