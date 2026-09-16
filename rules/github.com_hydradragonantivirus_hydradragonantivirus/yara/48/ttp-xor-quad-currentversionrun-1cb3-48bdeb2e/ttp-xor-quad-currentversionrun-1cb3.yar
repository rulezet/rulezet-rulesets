rule TTP_XOR_QUAD_CurrentVersionRun_1cb3 {
  strings:
    $key_1cb3 = { 4f dc [2] 6b d2 [2] 40 fe [2] 6e dc [2] 7a c7 [2] 75 dd [2] 6b c0 [2] 69 c1 [2] 72 c7 [2] 6e c0 [2] 72 ef }

  condition:
    any of them
}