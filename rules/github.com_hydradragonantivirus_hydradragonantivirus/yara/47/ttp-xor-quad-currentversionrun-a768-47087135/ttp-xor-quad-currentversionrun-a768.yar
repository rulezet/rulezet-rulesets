rule TTP_XOR_QUAD_CurrentVersionRun_a768 {
  strings:
    $key_a768 = { f4 07 [2] d0 09 [2] fb 25 [2] d5 07 [2] c1 1c [2] ce 06 [2] d0 1b [2] d2 1a [2] c9 1c [2] d5 1b [2] c9 34 }

  condition:
    any of them
}