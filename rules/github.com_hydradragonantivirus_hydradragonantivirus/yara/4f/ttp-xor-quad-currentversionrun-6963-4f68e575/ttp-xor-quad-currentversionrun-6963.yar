rule TTP_XOR_QUAD_CurrentVersionRun_6963 {
  strings:
    $key_6963 = { 3a 0c [2] 1e 02 [2] 35 2e [2] 1b 0c [2] 0f 17 [2] 00 0d [2] 1e 10 [2] 1c 11 [2] 07 17 [2] 1b 10 [2] 07 3f }

  condition:
    any of them
}