rule TTP_XOR_QUAD_CurrentVersionRun_5ab3 {
  strings:
    $key_5ab3 = { 09 dc [2] 2d d2 [2] 06 fe [2] 28 dc [2] 3c c7 [2] 33 dd [2] 2d c0 [2] 2f c1 [2] 34 c7 [2] 28 c0 [2] 34 ef }

  condition:
    any of them
}