rule TTP_XOR_QUAD_CurrentVersionRun_7c41 {
  strings:
    $key_7c41 = { 2f 2e [2] 0b 20 [2] 20 0c [2] 0e 2e [2] 1a 35 [2] 15 2f [2] 0b 32 [2] 09 33 [2] 12 35 [2] 0e 32 [2] 12 1d }

  condition:
    any of them
}