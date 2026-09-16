rule TTP_XOR_QUAD_CurrentVersionRun_0c41 {
  strings:
    $key_0c41 = { 5f 2e [2] 7b 20 [2] 50 0c [2] 7e 2e [2] 6a 35 [2] 65 2f [2] 7b 32 [2] 79 33 [2] 62 35 [2] 7e 32 [2] 62 1d }

  condition:
    any of them
}