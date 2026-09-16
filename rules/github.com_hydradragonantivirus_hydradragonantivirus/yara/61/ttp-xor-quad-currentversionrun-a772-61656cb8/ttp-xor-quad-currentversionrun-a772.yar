rule TTP_XOR_QUAD_CurrentVersionRun_a772 {
  strings:
    $key_a772 = { f4 1d [2] d0 13 [2] fb 3f [2] d5 1d [2] c1 06 [2] ce 1c [2] d0 01 [2] d2 00 [2] c9 06 [2] d5 01 [2] c9 2e }

  condition:
    any of them
}