rule TTP_XOR_QUAD_CurrentVersionRun_a7e6 {
  strings:
    $key_a7e6 = { f4 89 [2] d0 87 [2] fb ab [2] d5 89 [2] c1 92 [2] ce 88 [2] d0 95 [2] d2 94 [2] c9 92 [2] d5 95 [2] c9 ba }

  condition:
    any of them
}