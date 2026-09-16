rule TTP_XOR_QUAD_CurrentVersionRun_a762 {
  strings:
    $key_a762 = { f4 0d [2] d0 03 [2] fb 2f [2] d5 0d [2] c1 16 [2] ce 0c [2] d0 11 [2] d2 10 [2] c9 16 [2] d5 11 [2] c9 3e }

  condition:
    any of them
}