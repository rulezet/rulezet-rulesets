rule TTP_XOR_QUAD_CurrentVersionRun_a614 {
  strings:
    $key_a614 = { f5 7b [2] d1 75 [2] fa 59 [2] d4 7b [2] c0 60 [2] cf 7a [2] d1 67 [2] d3 66 [2] c8 60 [2] d4 67 [2] c8 48 }

  condition:
    any of them
}