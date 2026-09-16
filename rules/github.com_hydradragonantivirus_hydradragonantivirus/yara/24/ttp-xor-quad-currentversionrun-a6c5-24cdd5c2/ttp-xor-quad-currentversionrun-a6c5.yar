rule TTP_XOR_QUAD_CurrentVersionRun_a6c5 {
  strings:
    $key_a6c5 = { f5 aa [2] d1 a4 [2] fa 88 [2] d4 aa [2] c0 b1 [2] cf ab [2] d1 b6 [2] d3 b7 [2] c8 b1 [2] d4 b6 [2] c8 99 }

  condition:
    any of them
}