rule TTP_XOR_QUAD_CurrentVersionRun_a6e4 {
  strings:
    $key_a6e4 = { f5 8b [2] d1 85 [2] fa a9 [2] d4 8b [2] c0 90 [2] cf 8a [2] d1 97 [2] d3 96 [2] c8 90 [2] d4 97 [2] c8 b8 }

  condition:
    any of them
}