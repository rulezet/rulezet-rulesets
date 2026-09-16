rule TTP_XOR_QUAD_CurrentVersionRun_7db3 {
  strings:
    $key_7db3 = { 2e dc [2] 0a d2 [2] 21 fe [2] 0f dc [2] 1b c7 [2] 14 dd [2] 0a c0 [2] 08 c1 [2] 13 c7 [2] 0f c0 [2] 13 ef }

  condition:
    any of them
}