rule TTP_XOR_QUAD_CurrentVersionRun_e38f {
  strings:
    $key_e38f = { b0 e0 [2] 94 ee [2] bf c2 [2] 91 e0 [2] 85 fb [2] 8a e1 [2] 94 fc [2] 96 fd [2] 8d fb [2] 91 fc [2] 8d d3 }

  condition:
    any of them
}