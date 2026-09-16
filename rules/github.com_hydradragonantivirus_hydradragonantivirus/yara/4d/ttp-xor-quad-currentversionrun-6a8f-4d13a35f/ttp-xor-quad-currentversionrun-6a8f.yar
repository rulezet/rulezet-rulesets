rule TTP_XOR_QUAD_CurrentVersionRun_6a8f {
  strings:
    $key_6a8f = { 39 e0 [2] 1d ee [2] 36 c2 [2] 18 e0 [2] 0c fb [2] 03 e1 [2] 1d fc [2] 1f fd [2] 04 fb [2] 18 fc [2] 04 d3 }

  condition:
    any of them
}