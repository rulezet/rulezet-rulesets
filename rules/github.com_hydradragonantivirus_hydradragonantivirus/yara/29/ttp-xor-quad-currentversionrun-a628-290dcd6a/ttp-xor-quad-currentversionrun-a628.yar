rule TTP_XOR_QUAD_CurrentVersionRun_a628 {
  strings:
    $key_a628 = { f5 47 [2] d1 49 [2] fa 65 [2] d4 47 [2] c0 5c [2] cf 46 [2] d1 5b [2] d3 5a [2] c8 5c [2] d4 5b [2] c8 74 }

  condition:
    any of them
}