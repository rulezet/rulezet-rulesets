rule TTP_XOR_QUAD_CurrentVersionRun_a756 {
  strings:
    $key_a756 = { f4 39 [2] d0 37 [2] fb 1b [2] d5 39 [2] c1 22 [2] ce 38 [2] d0 25 [2] d2 24 [2] c9 22 [2] d5 25 [2] c9 0a }

  condition:
    any of them
}