rule TTP_XOR_QUAD_CurrentVersionRun_a723 {
  strings:
    $key_a723 = { f4 4c [2] d0 42 [2] fb 6e [2] d5 4c [2] c1 57 [2] ce 4d [2] d0 50 [2] d2 51 [2] c9 57 [2] d5 50 [2] c9 7f }

  condition:
    any of them
}