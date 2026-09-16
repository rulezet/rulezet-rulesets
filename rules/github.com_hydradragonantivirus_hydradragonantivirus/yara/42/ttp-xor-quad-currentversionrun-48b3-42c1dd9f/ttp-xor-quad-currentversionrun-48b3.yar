rule TTP_XOR_QUAD_CurrentVersionRun_48b3 {
  strings:
    $key_48b3 = { 1b dc [2] 3f d2 [2] 14 fe [2] 3a dc [2] 2e c7 [2] 21 dd [2] 3f c0 [2] 3d c1 [2] 26 c7 [2] 3a c0 [2] 26 ef }

  condition:
    any of them
}