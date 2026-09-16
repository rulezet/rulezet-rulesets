rule TTP_XOR_QUAD_CurrentVersionRun_6d41 {
  strings:
    $key_6d41 = { 3e 2e [2] 1a 20 [2] 31 0c [2] 1f 2e [2] 0b 35 [2] 04 2f [2] 1a 32 [2] 18 33 [2] 03 35 [2] 1f 32 [2] 03 1d }

  condition:
    any of them
}