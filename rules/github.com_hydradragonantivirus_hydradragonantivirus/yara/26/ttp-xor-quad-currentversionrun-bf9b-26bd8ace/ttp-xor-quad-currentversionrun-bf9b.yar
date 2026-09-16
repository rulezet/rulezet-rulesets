rule TTP_XOR_QUAD_CurrentVersionRun_bf9b {
  strings:
    $key_bf9b = { ec f4 [2] c8 fa [2] e3 d6 [2] cd f4 [2] d9 ef [2] d6 f5 [2] c8 e8 [2] ca e9 [2] d1 ef [2] cd e8 [2] d1 c7 }

  condition:
    any of them
}