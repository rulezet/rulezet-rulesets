rule TTP_XOR_QUAD_CurrentVersionRun_298f {
  strings:
    $key_298f = { 7a e0 [2] 5e ee [2] 75 c2 [2] 5b e0 [2] 4f fb [2] 40 e1 [2] 5e fc [2] 5c fd [2] 47 fb [2] 5b fc [2] 47 d3 }

  condition:
    any of them
}