rule TTP_XOR_QUAD_CurrentVersionRun_a716 {
  strings:
    $key_a716 = { f4 79 [2] d0 77 [2] fb 5b [2] d5 79 [2] c1 62 [2] ce 78 [2] d0 65 [2] d2 64 [2] c9 62 [2] d5 65 [2] c9 4a }

  condition:
    any of them
}