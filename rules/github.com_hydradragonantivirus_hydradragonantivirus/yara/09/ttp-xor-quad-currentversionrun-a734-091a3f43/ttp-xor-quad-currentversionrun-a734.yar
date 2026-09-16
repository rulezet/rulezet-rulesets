rule TTP_XOR_QUAD_CurrentVersionRun_a734 {
  strings:
    $key_a734 = { f4 5b [2] d0 55 [2] fb 79 [2] d5 5b [2] c1 40 [2] ce 5a [2] d0 47 [2] d2 46 [2] c9 40 [2] d5 47 [2] c9 68 }

  condition:
    any of them
}