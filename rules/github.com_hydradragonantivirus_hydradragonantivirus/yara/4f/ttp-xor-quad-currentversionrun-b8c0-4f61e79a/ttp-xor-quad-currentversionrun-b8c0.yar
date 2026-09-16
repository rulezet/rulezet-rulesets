rule TTP_XOR_QUAD_CurrentVersionRun_b8c0 {
  strings:
    $key_b8c0 = { eb af [2] cf a1 [2] e4 8d [2] ca af [2] de b4 [2] d1 ae [2] cf b3 [2] cd b2 [2] d6 b4 [2] ca b3 [2] d6 9c }

  condition:
    any of them
}