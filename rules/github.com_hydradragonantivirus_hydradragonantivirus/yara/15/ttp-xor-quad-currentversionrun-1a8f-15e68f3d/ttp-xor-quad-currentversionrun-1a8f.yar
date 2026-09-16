rule TTP_XOR_QUAD_CurrentVersionRun_1a8f {
  strings:
    $key_1a8f = { 49 e0 [2] 6d ee [2] 46 c2 [2] 68 e0 [2] 7c fb [2] 73 e1 [2] 6d fc [2] 6f fd [2] 74 fb [2] 68 fc [2] 74 d3 }

  condition:
    any of them
}