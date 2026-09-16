rule TTP_XOR_QUAD_CurrentVersionRun_a49a {
  strings:
    $key_a49a = { f7 f5 [2] d3 fb [2] f8 d7 [2] d6 f5 [2] c2 ee [2] cd f4 [2] d3 e9 [2] d1 e8 [2] ca ee [2] d6 e9 [2] ca c6 }

  condition:
    any of them
}