rule TTP_XOR_QUAD_CurrentVersionRun_d58f {
  strings:
    $key_d58f = { 86 e0 [2] a2 ee [2] 89 c2 [2] a7 e0 [2] b3 fb [2] bc e1 [2] a2 fc [2] a0 fd [2] bb fb [2] a7 fc [2] bb d3 }

  condition:
    any of them
}