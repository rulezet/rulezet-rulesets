rule TTP_XOR_QUAD_CurrentVersionRun_f28f {
  strings:
    $key_f28f = { a1 e0 [2] 85 ee [2] ae c2 [2] 80 e0 [2] 94 fb [2] 9b e1 [2] 85 fc [2] 87 fd [2] 9c fb [2] 80 fc [2] 9c d3 }

  condition:
    any of them
}