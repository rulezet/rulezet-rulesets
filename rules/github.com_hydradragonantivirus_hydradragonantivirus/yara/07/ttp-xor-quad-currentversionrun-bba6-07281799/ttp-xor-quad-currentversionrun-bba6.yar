rule TTP_XOR_QUAD_CurrentVersionRun_bba6 {
  strings:
    $key_bba6 = { e8 c9 [2] cc c7 [2] e7 eb [2] c9 c9 [2] dd d2 [2] d2 c8 [2] cc d5 [2] ce d4 [2] d5 d2 [2] c9 d5 [2] d5 fa }

  condition:
    any of them
}