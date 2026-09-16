rule TTP_XOR_QUAD_CurrentVersionRun_a3c0 {
  strings:
    $key_a3c0 = { f0 af [2] d4 a1 [2] ff 8d [2] d1 af [2] c5 b4 [2] ca ae [2] d4 b3 [2] d6 b2 [2] cd b4 [2] d1 b3 [2] cd 9c }

  condition:
    any of them
}