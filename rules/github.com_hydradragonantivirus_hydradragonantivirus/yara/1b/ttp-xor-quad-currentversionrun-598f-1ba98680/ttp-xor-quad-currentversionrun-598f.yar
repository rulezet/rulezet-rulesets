rule TTP_XOR_QUAD_CurrentVersionRun_598f {
  strings:
    $key_598f = { 0a e0 [2] 2e ee [2] 05 c2 [2] 2b e0 [2] 3f fb [2] 30 e1 [2] 2e fc [2] 2c fd [2] 37 fb [2] 2b fc [2] 37 d3 }

  condition:
    any of them
}