rule TTP_XOR_QUAD_CurrentVersionRun_a394 {
  strings:
    $key_a394 = { f0 fb [2] d4 f5 [2] ff d9 [2] d1 fb [2] c5 e0 [2] ca fa [2] d4 e7 [2] d6 e6 [2] cd e0 [2] d1 e7 [2] cd c8 }

  condition:
    any of them
}