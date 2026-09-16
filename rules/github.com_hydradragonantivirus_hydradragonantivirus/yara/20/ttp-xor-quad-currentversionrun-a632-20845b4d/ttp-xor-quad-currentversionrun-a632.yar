rule TTP_XOR_QUAD_CurrentVersionRun_a632 {
  strings:
    $key_a632 = { f5 5d [2] d1 53 [2] fa 7f [2] d4 5d [2] c0 46 [2] cf 5c [2] d1 41 [2] d3 40 [2] c8 46 [2] d4 41 [2] c8 6e }

  condition:
    any of them
}