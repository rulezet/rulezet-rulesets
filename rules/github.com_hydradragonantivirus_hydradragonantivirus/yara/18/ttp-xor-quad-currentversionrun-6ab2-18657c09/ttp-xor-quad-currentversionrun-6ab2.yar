rule TTP_XOR_QUAD_CurrentVersionRun_6ab2 {
  strings:
    $key_6ab2 = { 39 dd [2] 1d d3 [2] 36 ff [2] 18 dd [2] 0c c6 [2] 03 dc [2] 1d c1 [2] 1f c0 [2] 04 c6 [2] 18 c1 [2] 04 ee }

  condition:
    any of them
}