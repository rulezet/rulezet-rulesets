rule TTP_XOR_QUAD_CurrentVersionRun_138f {
  strings:
    $key_138f = { 40 e0 [2] 64 ee [2] 4f c2 [2] 61 e0 [2] 75 fb [2] 7a e1 [2] 64 fc [2] 66 fd [2] 7d fb [2] 61 fc [2] 7d d3 }

  condition:
    any of them
}