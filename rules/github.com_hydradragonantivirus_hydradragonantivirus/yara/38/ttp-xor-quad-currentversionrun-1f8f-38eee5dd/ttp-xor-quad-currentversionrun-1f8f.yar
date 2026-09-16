rule TTP_XOR_QUAD_CurrentVersionRun_1f8f {
  strings:
    $key_1f8f = { 4c e0 [2] 68 ee [2] 43 c2 [2] 6d e0 [2] 79 fb [2] 76 e1 [2] 68 fc [2] 6a fd [2] 71 fb [2] 6d fc [2] 71 d3 }

  condition:
    any of them
}