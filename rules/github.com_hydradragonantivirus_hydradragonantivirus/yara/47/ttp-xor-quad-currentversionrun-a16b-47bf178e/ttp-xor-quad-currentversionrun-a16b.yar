rule TTP_XOR_QUAD_CurrentVersionRun_a16b {
  strings:
    $key_a16b = { f2 04 [2] d6 0a [2] fd 26 [2] d3 04 [2] c7 1f [2] c8 05 [2] d6 18 [2] d4 19 [2] cf 1f [2] d3 18 [2] cf 37 }

  condition:
    any of them
}