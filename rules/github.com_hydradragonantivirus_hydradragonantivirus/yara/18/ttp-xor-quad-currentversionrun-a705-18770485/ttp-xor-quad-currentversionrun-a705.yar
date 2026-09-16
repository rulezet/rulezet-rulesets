rule TTP_XOR_QUAD_CurrentVersionRun_a705 {
  strings:
    $key_a705 = { f4 6a [2] d0 64 [2] fb 48 [2] d5 6a [2] c1 71 [2] ce 6b [2] d0 76 [2] d2 77 [2] c9 71 [2] d5 76 [2] c9 59 }

  condition:
    any of them
}