rule TTP_XOR_QUAD_CurrentVersionRun_a765 {
  strings:
    $key_a765 = { f4 0a [2] d0 04 [2] fb 28 [2] d5 0a [2] c1 11 [2] ce 0b [2] d0 16 [2] d2 17 [2] c9 11 [2] d5 16 [2] c9 39 }

  condition:
    any of them
}