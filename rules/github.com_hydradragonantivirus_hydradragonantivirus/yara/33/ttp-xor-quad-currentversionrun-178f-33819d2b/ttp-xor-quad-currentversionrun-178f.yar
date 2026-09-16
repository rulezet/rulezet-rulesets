rule TTP_XOR_QUAD_CurrentVersionRun_178f {
  strings:
    $key_178f = { 44 e0 [2] 60 ee [2] 4b c2 [2] 65 e0 [2] 71 fb [2] 7e e1 [2] 60 fc [2] 62 fd [2] 79 fb [2] 65 fc [2] 79 d3 }

  condition:
    any of them
}