rule TTP_XOR_QUAD_CurrentVersionRun_b19a {
  strings:
    $key_b19a = { e2 f5 [2] c6 fb [2] ed d7 [2] c3 f5 [2] d7 ee [2] d8 f4 [2] c6 e9 [2] c4 e8 [2] df ee [2] c3 e9 [2] df c6 }

  condition:
    any of them
}