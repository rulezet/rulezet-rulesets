rule TTP_XOR_QUAD_CurrentVersionRun_a7e0 {
  strings:
    $key_a7e0 = { f4 8f [2] d0 81 [2] fb ad [2] d5 8f [2] c1 94 [2] ce 8e [2] d0 93 [2] d2 92 [2] c9 94 [2] d5 93 [2] c9 bc }

  condition:
    any of them
}