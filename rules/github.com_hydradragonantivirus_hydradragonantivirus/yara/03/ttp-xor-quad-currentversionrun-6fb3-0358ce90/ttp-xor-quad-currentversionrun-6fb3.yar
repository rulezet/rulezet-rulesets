rule TTP_XOR_QUAD_CurrentVersionRun_6fb3 {
  strings:
    $key_6fb3 = { 3c dc [2] 18 d2 [2] 33 fe [2] 1d dc [2] 09 c7 [2] 06 dd [2] 18 c0 [2] 1a c1 [2] 01 c7 [2] 1d c0 [2] 01 ef }

  condition:
    any of them
}