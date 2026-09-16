rule TTP_XOR_QUAD_CurrentVersionRun_ce8f {
  strings:
    $key_ce8f = { 9d e0 [2] b9 ee [2] 92 c2 [2] bc e0 [2] a8 fb [2] a7 e1 [2] b9 fc [2] bb fd [2] a0 fb [2] bc fc [2] a0 d3 }

  condition:
    any of them
}