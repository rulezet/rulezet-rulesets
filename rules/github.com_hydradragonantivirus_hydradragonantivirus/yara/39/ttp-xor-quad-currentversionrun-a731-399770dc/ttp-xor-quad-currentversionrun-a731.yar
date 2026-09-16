rule TTP_XOR_QUAD_CurrentVersionRun_a731 {
  strings:
    $key_a731 = { f4 5e [2] d0 50 [2] fb 7c [2] d5 5e [2] c1 45 [2] ce 5f [2] d0 42 [2] d2 43 [2] c9 45 [2] d5 42 [2] c9 6d }

  condition:
    any of them
}