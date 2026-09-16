rule TTP_XOR_QUAD_CurrentVersionRun_a714 {
  strings:
    $key_a714 = { f4 7b [2] d0 75 [2] fb 59 [2] d5 7b [2] c1 60 [2] ce 7a [2] d0 67 [2] d2 66 [2] c9 60 [2] d5 67 [2] c9 48 }

  condition:
    any of them
}