rule TTP_XOR_QUAD_CurrentVersionRun_a179 {
  strings:
    $key_a179 = { f2 16 [2] d6 18 [2] fd 34 [2] d3 16 [2] c7 0d [2] c8 17 [2] d6 0a [2] d4 0b [2] cf 0d [2] d3 0a [2] cf 25 }

  condition:
    any of them
}