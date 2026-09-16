rule TTP_XOR_QUAD_CurrentVersionRun_a634 {
  strings:
    $key_a634 = { f5 5b [2] d1 55 [2] fa 79 [2] d4 5b [2] c0 40 [2] cf 5a [2] d1 47 [2] d3 46 [2] c8 40 [2] d4 47 [2] c8 68 }

  condition:
    any of them
}