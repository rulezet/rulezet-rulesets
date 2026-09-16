rule TTP_XOR_QUAD_CurrentVersionRun_e8b3 {
  strings:
    $key_e8b3 = { bb dc [2] 9f d2 [2] b4 fe [2] 9a dc [2] 8e c7 [2] 81 dd [2] 9f c0 [2] 9d c1 [2] 86 c7 [2] 9a c0 [2] 86 ef }

  condition:
    any of them
}