rule TTP_XOR_QUAD_CurrentVersionRun_4d41 {
  strings:
    $key_4d41 = { 1e 2e [2] 3a 20 [2] 11 0c [2] 3f 2e [2] 2b 35 [2] 24 2f [2] 3a 32 [2] 38 33 [2] 23 35 [2] 3f 32 [2] 23 1d }

  condition:
    any of them
}