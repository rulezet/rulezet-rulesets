rule TTP_XOR_QUAD_CurrentVersionRun_08b3 {
  strings:
    $key_08b3 = { 5b dc [2] 7f d2 [2] 54 fe [2] 7a dc [2] 6e c7 [2] 61 dd [2] 7f c0 [2] 7d c1 [2] 66 c7 [2] 7a c0 [2] 66 ef }

  condition:
    any of them
}