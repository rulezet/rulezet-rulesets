rule TTP_XOR_QUAD_CurrentVersionRun_aa9d {
  strings:
    $key_aa9d = { f9 f2 [2] dd fc [2] f6 d0 [2] d8 f2 [2] cc e9 [2] c3 f3 [2] dd ee [2] df ef [2] c4 e9 [2] d8 ee [2] c4 c1 }

  condition:
    any of them
}