rule TTP_XOR_QUAD_CurrentVersionRun_ea8f {
  strings:
    $key_ea8f = { b9 e0 [2] 9d ee [2] b6 c2 [2] 98 e0 [2] 8c fb [2] 83 e1 [2] 9d fc [2] 9f fd [2] 84 fb [2] 98 fc [2] 84 d3 }

  condition:
    any of them
}