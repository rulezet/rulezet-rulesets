rule TTP_XOR_QUAD_CurrentVersionRun_a0e6 {
  strings:
    $key_a0e6 = { f3 89 [2] d7 87 [2] fc ab [2] d2 89 [2] c6 92 [2] c9 88 [2] d7 95 [2] d5 94 [2] ce 92 [2] d2 95 [2] ce ba }

  condition:
    any of them
}