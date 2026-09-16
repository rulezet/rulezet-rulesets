rule TTP_XOR_QUAD_CurrentVersionRun_4b8f {
  strings:
    $key_4b8f = { 18 e0 [2] 3c ee [2] 17 c2 [2] 39 e0 [2] 2d fb [2] 22 e1 [2] 3c fc [2] 3e fd [2] 25 fb [2] 39 fc [2] 25 d3 }

  condition:
    any of them
}