rule TTP_XOR_QUAD_CurrentVersionRun_6941 {
  strings:
    $key_6941 = { 3a 2e [2] 1e 20 [2] 35 0c [2] 1b 2e [2] 0f 35 [2] 00 2f [2] 1e 32 [2] 1c 33 [2] 07 35 [2] 1b 32 [2] 07 1d }

  condition:
    any of them
}