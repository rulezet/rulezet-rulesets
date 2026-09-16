rule TTP_XOR_QUAD_CurrentVersionRun_a7ed {
  strings:
    $key_a7ed = { f4 82 [2] d0 8c [2] fb a0 [2] d5 82 [2] c1 99 [2] ce 83 [2] d0 9e [2] d2 9f [2] c9 99 [2] d5 9e [2] c9 b1 }

  condition:
    any of them
}