rule TTP_XOR_QUAD_CurrentVersionRun_bf9a {
  strings:
    $key_bf9a = { ec f5 [2] c8 fb [2] e3 d7 [2] cd f5 [2] d9 ee [2] d6 f4 [2] c8 e9 [2] ca e8 [2] d1 ee [2] cd e9 [2] d1 c6 }

  condition:
    any of them
}