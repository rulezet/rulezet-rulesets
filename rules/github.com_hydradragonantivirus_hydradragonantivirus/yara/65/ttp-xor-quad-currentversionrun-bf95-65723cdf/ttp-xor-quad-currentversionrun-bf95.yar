rule TTP_XOR_QUAD_CurrentVersionRun_bf95 {
  strings:
    $key_bf95 = { ec fa [2] c8 f4 [2] e3 d8 [2] cd fa [2] d9 e1 [2] d6 fb [2] c8 e6 [2] ca e7 [2] d1 e1 [2] cd e6 [2] d1 c9 }

  condition:
    any of them
}