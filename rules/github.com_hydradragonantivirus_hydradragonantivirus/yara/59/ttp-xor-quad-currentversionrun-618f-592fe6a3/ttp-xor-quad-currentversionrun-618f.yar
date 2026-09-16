rule TTP_XOR_QUAD_CurrentVersionRun_618f {
  strings:
    $key_618f = { 32 e0 [2] 16 ee [2] 3d c2 [2] 13 e0 [2] 07 fb [2] 08 e1 [2] 16 fc [2] 14 fd [2] 0f fb [2] 13 fc [2] 0f d3 }

  condition:
    any of them
}