rule TTP_XOR_QUAD_CurrentVersionRun_a7c1 {
  strings:
    $key_a7c1 = { f4 ae [2] d0 a0 [2] fb 8c [2] d5 ae [2] c1 b5 [2] ce af [2] d0 b2 [2] d2 b3 [2] c9 b5 [2] d5 b2 [2] c9 9d }

  condition:
    any of them
}