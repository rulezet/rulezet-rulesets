rule TTP_XOR_QUAD_CurrentVersionRun_068f {
  strings:
    $key_068f = { 55 e0 [2] 71 ee [2] 5a c2 [2] 74 e0 [2] 60 fb [2] 6f e1 [2] 71 fc [2] 73 fd [2] 68 fb [2] 74 fc [2] 68 d3 }

  condition:
    any of them
}