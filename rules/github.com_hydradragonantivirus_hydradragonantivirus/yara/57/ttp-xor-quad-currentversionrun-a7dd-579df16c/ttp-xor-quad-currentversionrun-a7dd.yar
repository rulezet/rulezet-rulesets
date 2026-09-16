rule TTP_XOR_QUAD_CurrentVersionRun_a7dd {
  strings:
    $key_a7dd = { f4 b2 [2] d0 bc [2] fb 90 [2] d5 b2 [2] c1 a9 [2] ce b3 [2] d0 ae [2] d2 af [2] c9 a9 [2] d5 ae [2] c9 81 }

  condition:
    any of them
}