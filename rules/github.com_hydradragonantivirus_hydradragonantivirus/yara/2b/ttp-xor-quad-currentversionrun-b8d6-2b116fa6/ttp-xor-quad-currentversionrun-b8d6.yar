rule TTP_XOR_QUAD_CurrentVersionRun_b8d6 {
  strings:
    $key_b8d6 = { eb b9 [2] cf b7 [2] e4 9b [2] ca b9 [2] de a2 [2] d1 b8 [2] cf a5 [2] cd a4 [2] d6 a2 [2] ca a5 [2] d6 8a }

  condition:
    any of them
}