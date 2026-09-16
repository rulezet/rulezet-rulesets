rule TTP_XOR_QUAD_CurrentVersionRun_1b8f {
  strings:
    $key_1b8f = { 48 e0 [2] 6c ee [2] 47 c2 [2] 69 e0 [2] 7d fb [2] 72 e1 [2] 6c fc [2] 6e fd [2] 75 fb [2] 69 fc [2] 75 d3 }

  condition:
    any of them
}