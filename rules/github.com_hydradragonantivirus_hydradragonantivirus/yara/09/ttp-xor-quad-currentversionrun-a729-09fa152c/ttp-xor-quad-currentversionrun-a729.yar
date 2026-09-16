rule TTP_XOR_QUAD_CurrentVersionRun_a729 {
  strings:
    $key_a729 = { f4 46 [2] d0 48 [2] fb 64 [2] d5 46 [2] c1 5d [2] ce 47 [2] d0 5a [2] d2 5b [2] c9 5d [2] d5 5a [2] c9 75 }

  condition:
    any of them
}