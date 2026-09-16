rule TTP_XOR_QUAD_CurrentVersionRun_e9b3 {
  strings:
    $key_e9b3 = { ba dc [2] 9e d2 [2] b5 fe [2] 9b dc [2] 8f c7 [2] 80 dd [2] 9e c0 [2] 9c c1 [2] 87 c7 [2] 9b c0 [2] 87 ef }

  condition:
    any of them
}