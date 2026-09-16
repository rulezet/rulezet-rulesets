rule TTP_XOR_QUAD_CurrentVersionRun_5d31 {
  strings:
    $key_5d31 = { 0e 5e [2] 2a 50 [2] 01 7c [2] 2f 5e [2] 3b 45 [2] 34 5f [2] 2a 42 [2] 28 43 [2] 33 45 [2] 2f 42 [2] 33 6d }

  condition:
    any of them
}