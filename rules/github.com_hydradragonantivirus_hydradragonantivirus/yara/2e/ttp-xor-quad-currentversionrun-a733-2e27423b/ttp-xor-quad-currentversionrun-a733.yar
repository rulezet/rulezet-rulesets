rule TTP_XOR_QUAD_CurrentVersionRun_a733 {
  strings:
    $key_a733 = { f4 5c [2] d0 52 [2] fb 7e [2] d5 5c [2] c1 47 [2] ce 5d [2] d0 40 [2] d2 41 [2] c9 47 [2] d5 40 [2] c9 6f }

  condition:
    any of them
}