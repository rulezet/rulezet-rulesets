rule TTP_XOR_QUAD_CurrentVersionRun_bbb3 {
  strings:
    $key_bbb3 = { e8 dc [2] cc d2 [2] e7 fe [2] c9 dc [2] dd c7 [2] d2 dd [2] cc c0 [2] ce c1 [2] d5 c7 [2] c9 c0 [2] d5 ef }

  condition:
    any of them
}