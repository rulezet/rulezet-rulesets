rule TTP_XOR_QUAD_CurrentVersionRun_7cb3 {
  strings:
    $key_7cb3 = { 2f dc [2] 0b d2 [2] 20 fe [2] 0e dc [2] 1a c7 [2] 15 dd [2] 0b c0 [2] 09 c1 [2] 12 c7 [2] 0e c0 [2] 12 ef }

  condition:
    any of them
}