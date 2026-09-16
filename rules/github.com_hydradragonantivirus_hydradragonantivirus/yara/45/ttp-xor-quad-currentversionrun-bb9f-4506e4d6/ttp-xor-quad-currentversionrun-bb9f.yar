rule TTP_XOR_QUAD_CurrentVersionRun_bb9f {
  strings:
    $key_bb9f = { e8 f0 [2] cc fe [2] e7 d2 [2] c9 f0 [2] dd eb [2] d2 f1 [2] cc ec [2] ce ed [2] d5 eb [2] c9 ec [2] d5 c3 }

  condition:
    any of them
}