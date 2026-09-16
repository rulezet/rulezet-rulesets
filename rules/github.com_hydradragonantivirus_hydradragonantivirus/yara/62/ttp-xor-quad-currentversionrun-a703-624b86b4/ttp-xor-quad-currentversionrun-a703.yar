rule TTP_XOR_QUAD_CurrentVersionRun_a703 {
  strings:
    $key_a703 = { f4 6c [2] d0 62 [2] fb 4e [2] d5 6c [2] c1 77 [2] ce 6d [2] d0 70 [2] d2 71 [2] c9 77 [2] d5 70 [2] c9 5f }

  condition:
    any of them
}