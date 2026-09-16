rule TTP_XOR_QUAD_CurrentVersionRun_3ab2 {
  strings:
    $key_3ab2 = { 69 dd [2] 4d d3 [2] 66 ff [2] 48 dd [2] 5c c6 [2] 53 dc [2] 4d c1 [2] 4f c0 [2] 54 c6 [2] 48 c1 [2] 54 ee }

  condition:
    any of them
}