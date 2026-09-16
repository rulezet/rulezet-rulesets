rule TTP_XOR_QUAD_CurrentVersionRun_7fb3 {
  strings:
    $key_7fb3 = { 2c dc [2] 08 d2 [2] 23 fe [2] 0d dc [2] 19 c7 [2] 16 dd [2] 08 c0 [2] 0a c1 [2] 11 c7 [2] 0d c0 [2] 11 ef }

  condition:
    any of them
}