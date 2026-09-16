rule TTP_XOR_QUAD_CurrentVersionRun_5231 {
  strings:
    $key_5231 = { 01 5e [2] 25 50 [2] 0e 7c [2] 20 5e [2] 34 45 [2] 3b 5f [2] 25 42 [2] 27 43 [2] 3c 45 [2] 20 42 [2] 3c 6d }

  condition:
    any of them
}