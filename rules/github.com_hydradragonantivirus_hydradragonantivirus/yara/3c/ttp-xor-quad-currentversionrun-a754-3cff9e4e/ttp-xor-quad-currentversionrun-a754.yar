rule TTP_XOR_QUAD_CurrentVersionRun_a754 {
  strings:
    $key_a754 = { f4 3b [2] d0 35 [2] fb 19 [2] d5 3b [2] c1 20 [2] ce 3a [2] d0 27 [2] d2 26 [2] c9 20 [2] d5 27 [2] c9 08 }

  condition:
    any of them
}