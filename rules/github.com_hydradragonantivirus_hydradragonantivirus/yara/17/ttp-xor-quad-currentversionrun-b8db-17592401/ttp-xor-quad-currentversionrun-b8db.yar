rule TTP_XOR_QUAD_CurrentVersionRun_b8db {
  strings:
    $key_b8db = { eb b4 [2] cf ba [2] e4 96 [2] ca b4 [2] de af [2] d1 b5 [2] cf a8 [2] cd a9 [2] d6 af [2] ca a8 [2] d6 87 }

  condition:
    any of them
}