rule TTP_XOR_QUAD_CurrentVersionRun_a138 {
  strings:
    $key_a138 = { f2 57 [2] d6 59 [2] fd 75 [2] d3 57 [2] c7 4c [2] c8 56 [2] d6 4b [2] d4 4a [2] cf 4c [2] d3 4b [2] cf 64 }

  condition:
    any of them
}