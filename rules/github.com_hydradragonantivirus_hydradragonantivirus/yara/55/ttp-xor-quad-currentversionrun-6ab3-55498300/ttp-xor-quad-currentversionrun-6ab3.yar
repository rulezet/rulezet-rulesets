rule TTP_XOR_QUAD_CurrentVersionRun_6ab3 {
  strings:
    $key_6ab3 = { 39 dc [2] 1d d2 [2] 36 fe [2] 18 dc [2] 0c c7 [2] 03 dd [2] 1d c0 [2] 1f c1 [2] 04 c7 [2] 18 c0 [2] 04 ef }

  condition:
    any of them
}