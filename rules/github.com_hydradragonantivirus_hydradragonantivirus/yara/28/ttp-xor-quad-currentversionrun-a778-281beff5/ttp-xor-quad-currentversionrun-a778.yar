rule TTP_XOR_QUAD_CurrentVersionRun_a778 {
  strings:
    $key_a778 = { f4 17 [2] d0 19 [2] fb 35 [2] d5 17 [2] c1 0c [2] ce 16 [2] d0 0b [2] d2 0a [2] c9 0c [2] d5 0b [2] c9 24 }

  condition:
    any of them
}