rule TTP_XOR_QUAD_CurrentVersionRun_6851 {
  strings:
    $key_6851 = { 3b 3e [2] 1f 30 [2] 34 1c [2] 1a 3e [2] 0e 25 [2] 01 3f [2] 1f 22 [2] 1d 23 [2] 06 25 [2] 1a 22 [2] 06 0d }

  condition:
    any of them
}