rule TTP_XOR_QUAD_CurrentVersionRun_ff8f {
  strings:
    $key_ff8f = { ac e0 [2] 88 ee [2] a3 c2 [2] 8d e0 [2] 99 fb [2] 96 e1 [2] 88 fc [2] 8a fd [2] 91 fb [2] 8d fc [2] 91 d3 }

  condition:
    any of them
}