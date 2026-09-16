rule TTP_XOR_QUAD_CurrentVersionRun_5eb3 {
  strings:
    $key_5eb3 = { 0d dc [2] 29 d2 [2] 02 fe [2] 2c dc [2] 38 c7 [2] 37 dd [2] 29 c0 [2] 2b c1 [2] 30 c7 [2] 2c c0 [2] 30 ef }

  condition:
    any of them
}