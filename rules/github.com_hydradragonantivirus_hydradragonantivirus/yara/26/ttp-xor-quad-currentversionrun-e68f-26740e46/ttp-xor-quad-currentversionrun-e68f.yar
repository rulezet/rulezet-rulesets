rule TTP_XOR_QUAD_CurrentVersionRun_e68f {
  strings:
    $key_e68f = { b5 e0 [2] 91 ee [2] ba c2 [2] 94 e0 [2] 80 fb [2] 8f e1 [2] 91 fc [2] 93 fd [2] 88 fb [2] 94 fc [2] 88 d3 }

  condition:
    any of them
}