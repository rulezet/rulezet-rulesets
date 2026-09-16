rule TTP_XOR_QUAD_CurrentVersionRun_bb81 {
  strings:
    $key_bb81 = { e8 ee [2] cc e0 [2] e7 cc [2] c9 ee [2] dd f5 [2] d2 ef [2] cc f2 [2] ce f3 [2] d5 f5 [2] c9 f2 [2] d5 dd }

  condition:
    any of them
}