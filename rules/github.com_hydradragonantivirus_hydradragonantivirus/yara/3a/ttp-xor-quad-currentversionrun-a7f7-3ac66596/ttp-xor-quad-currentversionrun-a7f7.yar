rule TTP_XOR_QUAD_CurrentVersionRun_a7f7 {
  strings:
    $key_a7f7 = { f4 98 [2] d0 96 [2] fb ba [2] d5 98 [2] c1 83 [2] ce 99 [2] d0 84 [2] d2 85 [2] c9 83 [2] d5 84 [2] c9 ab }

  condition:
    any of them
}