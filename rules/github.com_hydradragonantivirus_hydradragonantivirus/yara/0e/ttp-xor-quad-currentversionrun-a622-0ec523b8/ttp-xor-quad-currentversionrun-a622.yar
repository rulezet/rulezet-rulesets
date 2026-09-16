rule TTP_XOR_QUAD_CurrentVersionRun_a622 {
  strings:
    $key_a622 = { f5 4d [2] d1 43 [2] fa 6f [2] d4 4d [2] c0 56 [2] cf 4c [2] d1 51 [2] d3 50 [2] c8 56 [2] d4 51 [2] c8 7e }

  condition:
    any of them
}