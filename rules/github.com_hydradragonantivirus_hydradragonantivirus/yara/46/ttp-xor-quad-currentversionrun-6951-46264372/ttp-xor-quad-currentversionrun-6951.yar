rule TTP_XOR_QUAD_CurrentVersionRun_6951 {
  strings:
    $key_6951 = { 3a 3e [2] 1e 30 [2] 35 1c [2] 1b 3e [2] 0f 25 [2] 00 3f [2] 1e 22 [2] 1c 23 [2] 07 25 [2] 1b 22 [2] 07 0d }

  condition:
    any of them
}