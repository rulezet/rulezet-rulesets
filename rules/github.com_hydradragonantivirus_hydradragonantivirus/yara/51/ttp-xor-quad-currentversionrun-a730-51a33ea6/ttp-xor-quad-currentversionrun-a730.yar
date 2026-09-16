rule TTP_XOR_QUAD_CurrentVersionRun_a730 {
  strings:
    $key_a730 = { f4 5f [2] d0 51 [2] fb 7d [2] d5 5f [2] c1 44 [2] ce 5e [2] d0 43 [2] d2 42 [2] c9 44 [2] d5 43 [2] c9 6c }

  condition:
    any of them
}