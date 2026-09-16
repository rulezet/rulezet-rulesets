rule TTP_XOR_QUAD_CurrentVersionRun_a3e2 {
  strings:
    $key_a3e2 = { f0 8d [2] d4 83 [2] ff af [2] d1 8d [2] c5 96 [2] ca 8c [2] d4 91 [2] d6 90 [2] cd 96 [2] d1 91 [2] cd be }

  condition:
    any of them
}