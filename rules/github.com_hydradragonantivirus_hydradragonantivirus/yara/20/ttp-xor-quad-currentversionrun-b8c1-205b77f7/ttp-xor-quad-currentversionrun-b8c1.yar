rule TTP_XOR_QUAD_CurrentVersionRun_b8c1 {
  strings:
    $key_b8c1 = { eb ae [2] cf a0 [2] e4 8c [2] ca ae [2] de b5 [2] d1 af [2] cf b2 [2] cd b3 [2] d6 b5 [2] ca b2 [2] d6 9d }

  condition:
    any of them
}