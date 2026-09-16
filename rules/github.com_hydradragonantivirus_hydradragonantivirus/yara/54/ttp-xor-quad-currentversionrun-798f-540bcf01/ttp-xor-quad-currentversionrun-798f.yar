rule TTP_XOR_QUAD_CurrentVersionRun_798f {
  strings:
    $key_798f = { 2a e0 [2] 0e ee [2] 25 c2 [2] 0b e0 [2] 1f fb [2] 10 e1 [2] 0e fc [2] 0c fd [2] 17 fb [2] 0b fc [2] 17 d3 }

  condition:
    any of them
}