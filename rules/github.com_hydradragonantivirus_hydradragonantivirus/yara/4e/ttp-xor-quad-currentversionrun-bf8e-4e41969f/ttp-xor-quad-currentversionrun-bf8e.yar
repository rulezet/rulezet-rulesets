rule TTP_XOR_QUAD_CurrentVersionRun_bf8e {
  strings:
    $key_bf8e = { ec e1 [2] c8 ef [2] e3 c3 [2] cd e1 [2] d9 fa [2] d6 e0 [2] c8 fd [2] ca fc [2] d1 fa [2] cd fd [2] d1 d2 }

  condition:
    any of them
}