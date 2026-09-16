rule TTP_XOR_QUAD_CurrentVersionRun_5931 {
  strings:
    $key_5931 = { 0a 5e [2] 2e 50 [2] 05 7c [2] 2b 5e [2] 3f 45 [2] 30 5f [2] 2e 42 [2] 2c 43 [2] 37 45 [2] 2b 42 [2] 37 6d }

  condition:
    any of them
}