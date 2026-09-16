rule TTP_XOR_QUAD_CurrentVersionRun_0b41 {
  strings:
    $key_0b41 = { 58 2e [2] 7c 20 [2] 57 0c [2] 79 2e [2] 6d 35 [2] 62 2f [2] 7c 32 [2] 7e 33 [2] 65 35 [2] 79 32 [2] 65 1d }

  condition:
    any of them
}