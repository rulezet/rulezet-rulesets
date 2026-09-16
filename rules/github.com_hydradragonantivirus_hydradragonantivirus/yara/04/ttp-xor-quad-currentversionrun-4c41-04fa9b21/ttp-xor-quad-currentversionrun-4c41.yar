rule TTP_XOR_QUAD_CurrentVersionRun_4c41 {
  strings:
    $key_4c41 = { 1f 2e [2] 3b 20 [2] 10 0c [2] 3e 2e [2] 2a 35 [2] 25 2f [2] 3b 32 [2] 39 33 [2] 22 35 [2] 3e 32 [2] 22 1d }

  condition:
    any of them
}