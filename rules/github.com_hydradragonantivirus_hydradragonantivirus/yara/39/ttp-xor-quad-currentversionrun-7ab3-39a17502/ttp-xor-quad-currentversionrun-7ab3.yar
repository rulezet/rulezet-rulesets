rule TTP_XOR_QUAD_CurrentVersionRun_7ab3 {
  strings:
    $key_7ab3 = { 29 dc [2] 0d d2 [2] 26 fe [2] 08 dc [2] 1c c7 [2] 13 dd [2] 0d c0 [2] 0f c1 [2] 14 c7 [2] 08 c0 [2] 14 ef }

  condition:
    any of them
}