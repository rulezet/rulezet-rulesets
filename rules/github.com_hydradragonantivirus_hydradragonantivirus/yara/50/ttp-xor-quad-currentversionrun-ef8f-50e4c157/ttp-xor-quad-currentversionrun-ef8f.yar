rule TTP_XOR_QUAD_CurrentVersionRun_ef8f {
  strings:
    $key_ef8f = { bc e0 [2] 98 ee [2] b3 c2 [2] 9d e0 [2] 89 fb [2] 86 e1 [2] 98 fc [2] 9a fd [2] 81 fb [2] 9d fc [2] 81 d3 }

  condition:
    any of them
}