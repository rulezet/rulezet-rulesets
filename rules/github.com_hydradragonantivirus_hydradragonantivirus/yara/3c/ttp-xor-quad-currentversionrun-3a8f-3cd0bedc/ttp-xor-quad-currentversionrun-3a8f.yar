rule TTP_XOR_QUAD_CurrentVersionRun_3a8f {
  strings:
    $key_3a8f = { 69 e0 [2] 4d ee [2] 66 c2 [2] 48 e0 [2] 5c fb [2] 53 e1 [2] 4d fc [2] 4f fd [2] 54 fb [2] 48 fc [2] 54 d3 }

  condition:
    any of them
}