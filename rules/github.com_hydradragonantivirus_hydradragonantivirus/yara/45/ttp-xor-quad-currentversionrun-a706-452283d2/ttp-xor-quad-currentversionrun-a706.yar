rule TTP_XOR_QUAD_CurrentVersionRun_a706 {
  strings:
    $key_a706 = { f4 69 [2] d0 67 [2] fb 4b [2] d5 69 [2] c1 72 [2] ce 68 [2] d0 75 [2] d2 74 [2] c9 72 [2] d5 75 [2] c9 5a }

  condition:
    any of them
}