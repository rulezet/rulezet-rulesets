rule TTP_XOR_QUAD_CurrentVersionRun_bbb1 {
  strings:
    $key_bbb1 = { e8 de [2] cc d0 [2] e7 fc [2] c9 de [2] dd c5 [2] d2 df [2] cc c2 [2] ce c3 [2] d5 c5 [2] c9 c2 [2] d5 ed }

  condition:
    any of them
}