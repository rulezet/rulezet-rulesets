rule TTP_XOR_QUAD_CurrentVersionRun_a732 {
  strings:
    $key_a732 = { f4 5d [2] d0 53 [2] fb 7f [2] d5 5d [2] c1 46 [2] ce 5c [2] d0 41 [2] d2 40 [2] c9 46 [2] d5 41 [2] c9 6e }

  condition:
    any of them
}