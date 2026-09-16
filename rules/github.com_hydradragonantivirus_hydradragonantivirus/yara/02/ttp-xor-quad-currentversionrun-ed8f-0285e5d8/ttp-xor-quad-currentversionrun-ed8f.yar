rule TTP_XOR_QUAD_CurrentVersionRun_ed8f {
  strings:
    $key_ed8f = { be e0 [2] 9a ee [2] b1 c2 [2] 9f e0 [2] 8b fb [2] 84 e1 [2] 9a fc [2] 98 fd [2] 83 fb [2] 9f fc [2] 83 d3 }

  condition:
    any of them
}