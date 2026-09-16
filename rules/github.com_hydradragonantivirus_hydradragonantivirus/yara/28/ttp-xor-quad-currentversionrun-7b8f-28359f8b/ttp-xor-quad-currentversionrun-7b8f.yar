rule TTP_XOR_QUAD_CurrentVersionRun_7b8f {
  strings:
    $key_7b8f = { 28 e0 [2] 0c ee [2] 27 c2 [2] 09 e0 [2] 1d fb [2] 12 e1 [2] 0c fc [2] 0e fd [2] 15 fb [2] 09 fc [2] 15 d3 }

  condition:
    any of them
}