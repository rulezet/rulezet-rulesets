rule TTP_XOR_QUAD_CurrentVersionRun_7ab2 {
  strings:
    $key_7ab2 = { 29 dd [2] 0d d3 [2] 26 ff [2] 08 dd [2] 1c c6 [2] 13 dc [2] 0d c1 [2] 0f c0 [2] 14 c6 [2] 08 c1 [2] 14 ee }

  condition:
    any of them
}