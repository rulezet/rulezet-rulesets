rule TTP_XOR_QUAD_CurrentVersionRun_1fb3 {
  strings:
    $key_1fb3 = { 4c dc [2] 68 d2 [2] 43 fe [2] 6d dc [2] 79 c7 [2] 76 dd [2] 68 c0 [2] 6a c1 [2] 71 c7 [2] 6d c0 [2] 71 ef }

  condition:
    any of them
}