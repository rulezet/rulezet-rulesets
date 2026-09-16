rule TTP_XOR_QUAD_CurrentVersionRun_fd8f {
  strings:
    $key_fd8f = { ae e0 [2] 8a ee [2] a1 c2 [2] 8f e0 [2] 9b fb [2] 94 e1 [2] 8a fc [2] 88 fd [2] 93 fb [2] 8f fc [2] 93 d3 }

  condition:
    any of them
}