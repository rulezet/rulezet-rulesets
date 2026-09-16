rule TTP_XOR_QUAD_CurrentVersionRun_dd8f {
  strings:
    $key_dd8f = { 8e e0 [2] aa ee [2] 81 c2 [2] af e0 [2] bb fb [2] b4 e1 [2] aa fc [2] a8 fd [2] b3 fb [2] af fc [2] b3 d3 }

  condition:
    any of them
}