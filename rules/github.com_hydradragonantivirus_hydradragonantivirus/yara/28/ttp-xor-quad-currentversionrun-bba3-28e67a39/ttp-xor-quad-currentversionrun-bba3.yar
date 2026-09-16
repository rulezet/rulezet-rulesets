rule TTP_XOR_QUAD_CurrentVersionRun_bba3 {
  strings:
    $key_bba3 = { e8 cc [2] cc c2 [2] e7 ee [2] c9 cc [2] dd d7 [2] d2 cd [2] cc d0 [2] ce d1 [2] d5 d7 [2] c9 d0 [2] d5 ff }

  condition:
    any of them
}