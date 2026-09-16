rule TTP_XOR_QUAD_CurrentVersionRun_5b8f {
  strings:
    $key_5b8f = { 08 e0 [2] 2c ee [2] 07 c2 [2] 29 e0 [2] 3d fb [2] 32 e1 [2] 2c fc [2] 2e fd [2] 35 fb [2] 29 fc [2] 35 d3 }

  condition:
    any of them
}