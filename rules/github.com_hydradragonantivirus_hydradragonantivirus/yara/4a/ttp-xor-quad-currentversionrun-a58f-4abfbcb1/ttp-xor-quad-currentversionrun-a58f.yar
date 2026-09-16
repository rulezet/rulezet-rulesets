rule TTP_XOR_QUAD_CurrentVersionRun_a58f {
  strings:
    $key_a58f = { f6 e0 [2] d2 ee [2] f9 c2 [2] d7 e0 [2] c3 fb [2] cc e1 [2] d2 fc [2] d0 fd [2] cb fb [2] d7 fc [2] cb d3 }

  condition:
    any of them
}