rule TTP_XOR_QUAD_CurrentVersionRun_f98f {
  strings:
    $key_f98f = { aa e0 [2] 8e ee [2] a5 c2 [2] 8b e0 [2] 9f fb [2] 90 e1 [2] 8e fc [2] 8c fd [2] 97 fb [2] 8b fc [2] 97 d3 }

  condition:
    any of them
}