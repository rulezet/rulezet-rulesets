rule TTP_XOR_QUAD_CurrentVersionRun_398f {
  strings:
    $key_398f = { 6a e0 [2] 4e ee [2] 65 c2 [2] 4b e0 [2] 5f fb [2] 50 e1 [2] 4e fc [2] 4c fd [2] 57 fb [2] 4b fc [2] 57 d3 }

  condition:
    any of them
}