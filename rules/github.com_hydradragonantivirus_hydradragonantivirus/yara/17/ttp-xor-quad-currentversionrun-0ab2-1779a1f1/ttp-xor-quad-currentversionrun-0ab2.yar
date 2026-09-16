rule TTP_XOR_QUAD_CurrentVersionRun_0ab2 {
  strings:
    $key_0ab2 = { 59 dd [2] 7d d3 [2] 56 ff [2] 78 dd [2] 6c c6 [2] 63 dc [2] 7d c1 [2] 7f c0 [2] 64 c6 [2] 78 c1 [2] 64 ee }

  condition:
    any of them
}