rule TTP_XOR_QUAD_CurrentVersionRun_0cb3 {
  strings:
    $key_0cb3 = { 5f dc [2] 7b d2 [2] 50 fe [2] 7e dc [2] 6a c7 [2] 65 dd [2] 7b c0 [2] 79 c1 [2] 62 c7 [2] 7e c0 [2] 62 ef }

  condition:
    any of them
}