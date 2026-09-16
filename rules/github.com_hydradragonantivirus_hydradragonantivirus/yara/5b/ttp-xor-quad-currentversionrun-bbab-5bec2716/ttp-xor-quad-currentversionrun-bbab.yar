rule TTP_XOR_QUAD_CurrentVersionRun_bbab {
  strings:
    $key_bbab = { e8 c4 [2] cc ca [2] e7 e6 [2] c9 c4 [2] dd df [2] d2 c5 [2] cc d8 [2] ce d9 [2] d5 df [2] c9 d8 [2] d5 f7 }

  condition:
    any of them
}