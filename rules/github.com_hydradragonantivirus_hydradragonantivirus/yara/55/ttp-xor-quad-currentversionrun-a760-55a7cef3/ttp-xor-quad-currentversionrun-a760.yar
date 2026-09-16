rule TTP_XOR_QUAD_CurrentVersionRun_a760 {
  strings:
    $key_a760 = { f4 0f [2] d0 01 [2] fb 2d [2] d5 0f [2] c1 14 [2] ce 0e [2] d0 13 [2] d2 12 [2] c9 14 [2] d5 13 [2] c9 3c }

  condition:
    any of them
}