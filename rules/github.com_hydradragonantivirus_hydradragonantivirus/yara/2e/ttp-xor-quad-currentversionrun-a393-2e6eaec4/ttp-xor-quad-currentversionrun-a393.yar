rule TTP_XOR_QUAD_CurrentVersionRun_a393 {
  strings:
    $key_a393 = { f0 fc [2] d4 f2 [2] ff de [2] d1 fc [2] c5 e7 [2] ca fd [2] d4 e0 [2] d6 e1 [2] cd e7 [2] d1 e0 [2] cd cf }

  condition:
    any of them
}