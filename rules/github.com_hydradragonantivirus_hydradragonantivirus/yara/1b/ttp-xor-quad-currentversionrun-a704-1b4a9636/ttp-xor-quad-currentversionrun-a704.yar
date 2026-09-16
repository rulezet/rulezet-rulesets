rule TTP_XOR_QUAD_CurrentVersionRun_a704 {
  strings:
    $key_a704 = { f4 6b [2] d0 65 [2] fb 49 [2] d5 6b [2] c1 70 [2] ce 6a [2] d0 77 [2] d2 76 [2] c9 70 [2] d5 77 [2] c9 58 }

  condition:
    any of them
}