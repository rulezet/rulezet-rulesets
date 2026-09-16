rule TTP_XOR_QUAD_CurrentVersionRun_198f {
  strings:
    $key_198f = { 4a e0 [2] 6e ee [2] 45 c2 [2] 6b e0 [2] 7f fb [2] 70 e1 [2] 6e fc [2] 6c fd [2] 77 fb [2] 6b fc [2] 77 d3 }

  condition:
    any of them
}