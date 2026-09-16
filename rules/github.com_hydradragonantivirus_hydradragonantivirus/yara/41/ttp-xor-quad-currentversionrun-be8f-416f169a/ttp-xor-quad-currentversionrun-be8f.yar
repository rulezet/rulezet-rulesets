rule TTP_XOR_QUAD_CurrentVersionRun_be8f {
  strings:
    $key_be8f = { ed e0 [2] c9 ee [2] e2 c2 [2] cc e0 [2] d8 fb [2] d7 e1 [2] c9 fc [2] cb fd [2] d0 fb [2] cc fc [2] d0 d3 }

  condition:
    any of them
}