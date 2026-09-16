rule TTP_XOR_QUAD_CurrentVersionRun_a7fb {
  strings:
    $key_a7fb = { f4 94 [2] d0 9a [2] fb b6 [2] d5 94 [2] c1 8f [2] ce 95 [2] d0 88 [2] d2 89 [2] c9 8f [2] d5 88 [2] c9 a7 }

  condition:
    any of them
}