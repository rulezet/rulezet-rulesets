rule TTP_XOR_QUAD_CurrentVersionRun_0731 {
  strings:
    $key_0731 = { 54 5e [2] 70 50 [2] 5b 7c [2] 75 5e [2] 61 45 [2] 6e 5f [2] 70 42 [2] 72 43 [2] 69 45 [2] 75 42 [2] 69 6d }

  condition:
    any of them
}