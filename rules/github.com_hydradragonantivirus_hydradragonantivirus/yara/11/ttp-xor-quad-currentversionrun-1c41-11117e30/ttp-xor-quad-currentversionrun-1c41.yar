rule TTP_XOR_QUAD_CurrentVersionRun_1c41 {
  strings:
    $key_1c41 = { 4f 2e [2] 6b 20 [2] 40 0c [2] 6e 2e [2] 7a 35 [2] 75 2f [2] 6b 32 [2] 69 33 [2] 72 35 [2] 6e 32 [2] 72 1d }

  condition:
    any of them
}