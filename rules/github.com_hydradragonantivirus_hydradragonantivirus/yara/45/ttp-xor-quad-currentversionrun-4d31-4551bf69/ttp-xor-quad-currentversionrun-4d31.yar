rule TTP_XOR_QUAD_CurrentVersionRun_4d31 {
  strings:
    $key_4d31 = { 1e 5e [2] 3a 50 [2] 11 7c [2] 3f 5e [2] 2b 45 [2] 24 5f [2] 3a 42 [2] 38 43 [2] 23 45 [2] 3f 42 [2] 23 6d }

  condition:
    any of them
}