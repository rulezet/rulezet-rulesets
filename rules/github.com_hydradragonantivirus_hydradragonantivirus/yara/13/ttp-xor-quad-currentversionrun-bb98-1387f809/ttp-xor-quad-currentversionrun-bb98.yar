rule TTP_XOR_QUAD_CurrentVersionRun_bb98 {
  strings:
    $key_bb98 = { e8 f7 [2] cc f9 [2] e7 d5 [2] c9 f7 [2] dd ec [2] d2 f6 [2] cc eb [2] ce ea [2] d5 ec [2] c9 eb [2] d5 c4 }

  condition:
    any of them
}