rule TTP_XOR_QUAD_CurrentVersionRun_a739 {
  strings:
    $key_a739 = { f4 56 [2] d0 58 [2] fb 74 [2] d5 56 [2] c1 4d [2] ce 57 [2] d0 4a [2] d2 4b [2] c9 4d [2] d5 4a [2] c9 65 }

  condition:
    any of them
}