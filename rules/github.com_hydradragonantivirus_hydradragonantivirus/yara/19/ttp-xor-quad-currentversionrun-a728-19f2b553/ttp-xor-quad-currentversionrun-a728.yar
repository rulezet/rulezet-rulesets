rule TTP_XOR_QUAD_CurrentVersionRun_a728 {
  strings:
    $key_a728 = { f4 47 [2] d0 49 [2] fb 65 [2] d5 47 [2] c1 5c [2] ce 46 [2] d0 5b [2] d2 5a [2] c9 5c [2] d5 5b [2] c9 74 }

  condition:
    any of them
}