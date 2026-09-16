rule TTP_XOR_QUAD_CurrentVersionRun_bfc0 {
  strings:
    $key_bfc0 = { ec af [2] c8 a1 [2] e3 8d [2] cd af [2] d9 b4 [2] d6 ae [2] c8 b3 [2] ca b2 [2] d1 b4 [2] cd b3 [2] d1 9c }

  condition:
    any of them
}