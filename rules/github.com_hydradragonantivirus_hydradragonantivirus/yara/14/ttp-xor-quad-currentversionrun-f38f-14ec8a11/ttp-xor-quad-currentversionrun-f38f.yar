rule TTP_XOR_QUAD_CurrentVersionRun_f38f {
  strings:
    $key_f38f = { a0 e0 [2] 84 ee [2] af c2 [2] 81 e0 [2] 95 fb [2] 9a e1 [2] 84 fc [2] 86 fd [2] 9d fb [2] 81 fc [2] 9d d3 }

  condition:
    any of them
}