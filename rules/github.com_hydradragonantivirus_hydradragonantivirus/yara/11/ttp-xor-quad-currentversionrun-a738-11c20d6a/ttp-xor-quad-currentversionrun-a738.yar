rule TTP_XOR_QUAD_CurrentVersionRun_a738 {
  strings:
    $key_a738 = { f4 57 [2] d0 59 [2] fb 75 [2] d5 57 [2] c1 4c [2] ce 56 [2] d0 4b [2] d2 4a [2] c9 4c [2] d5 4b [2] c9 64 }

  condition:
    any of them
}