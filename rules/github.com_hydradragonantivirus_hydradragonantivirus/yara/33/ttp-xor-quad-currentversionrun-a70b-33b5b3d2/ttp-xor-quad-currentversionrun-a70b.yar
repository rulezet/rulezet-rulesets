rule TTP_XOR_QUAD_CurrentVersionRun_a70b {
  strings:
    $key_a70b = { f4 64 [2] d0 6a [2] fb 46 [2] d5 64 [2] c1 7f [2] ce 65 [2] d0 78 [2] d2 79 [2] c9 7f [2] d5 78 [2] c9 57 }

  condition:
    any of them
}