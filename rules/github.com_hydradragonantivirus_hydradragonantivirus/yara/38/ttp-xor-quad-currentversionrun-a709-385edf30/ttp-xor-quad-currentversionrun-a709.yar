rule TTP_XOR_QUAD_CurrentVersionRun_a709 {
  strings:
    $key_a709 = { f4 66 [2] d0 68 [2] fb 44 [2] d5 66 [2] c1 7d [2] ce 67 [2] d0 7a [2] d2 7b [2] c9 7d [2] d5 7a [2] c9 55 }

  condition:
    any of them
}