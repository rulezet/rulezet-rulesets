rule TTP_XOR_QUAD_CurrentVersionRun_7541 {
  strings:
    $key_7541 = { 26 2e [2] 02 20 [2] 29 0c [2] 07 2e [2] 13 35 [2] 1c 2f [2] 02 32 [2] 00 33 [2] 1b 35 [2] 07 32 [2] 1b 1d }

  condition:
    any of them
}