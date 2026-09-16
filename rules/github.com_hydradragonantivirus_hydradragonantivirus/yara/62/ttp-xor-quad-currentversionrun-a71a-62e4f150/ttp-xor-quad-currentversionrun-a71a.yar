rule TTP_XOR_QUAD_CurrentVersionRun_a71a {
  strings:
    $key_a71a = { f4 75 [2] d0 7b [2] fb 57 [2] d5 75 [2] c1 6e [2] ce 74 [2] d0 69 [2] d2 68 [2] c9 6e [2] d5 69 [2] c9 46 }

  condition:
    any of them
}