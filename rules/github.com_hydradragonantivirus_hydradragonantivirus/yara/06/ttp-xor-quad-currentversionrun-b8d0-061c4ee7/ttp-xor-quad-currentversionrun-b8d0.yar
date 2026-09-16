rule TTP_XOR_QUAD_CurrentVersionRun_b8d0 {
  strings:
    $key_b8d0 = { eb bf [2] cf b1 [2] e4 9d [2] ca bf [2] de a4 [2] d1 be [2] cf a3 [2] cd a2 [2] d6 a4 [2] ca a3 [2] d6 8c }

  condition:
    any of them
}