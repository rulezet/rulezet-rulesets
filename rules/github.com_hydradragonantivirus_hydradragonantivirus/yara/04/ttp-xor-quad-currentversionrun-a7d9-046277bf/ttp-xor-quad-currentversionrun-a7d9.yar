rule TTP_XOR_QUAD_CurrentVersionRun_a7d9 {
  strings:
    $key_a7d9 = { f4 b6 [2] d0 b8 [2] fb 94 [2] d5 b6 [2] c1 ad [2] ce b7 [2] d0 aa [2] d2 ab [2] c9 ad [2] d5 aa [2] c9 85 }

  condition:
    any of them
}