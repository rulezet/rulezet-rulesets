rule TTP_XOR_QUAD_CurrentVersionRun_ac9d {
  strings:
    $key_ac9d = { ff f2 [2] db fc [2] f0 d0 [2] de f2 [2] ca e9 [2] c5 f3 [2] db ee [2] d9 ef [2] c2 e9 [2] de ee [2] c2 c1 }

  condition:
    any of them
}