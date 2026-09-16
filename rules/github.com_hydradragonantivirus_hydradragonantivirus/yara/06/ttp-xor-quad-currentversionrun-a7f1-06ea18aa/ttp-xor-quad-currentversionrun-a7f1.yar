rule TTP_XOR_QUAD_CurrentVersionRun_a7f1 {
  strings:
    $key_a7f1 = { f4 9e [2] d0 90 [2] fb bc [2] d5 9e [2] c1 85 [2] ce 9f [2] d0 82 [2] d2 83 [2] c9 85 [2] d5 82 [2] c9 ad }

  condition:
    any of them
}