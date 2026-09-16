rule TTP_XOR_QUAD_CurrentVersionRun_a168 {
  strings:
    $key_a168 = { f2 07 [2] d6 09 [2] fd 25 [2] d3 07 [2] c7 1c [2] c8 06 [2] d6 1b [2] d4 1a [2] cf 1c [2] d3 1b [2] cf 34 }

  condition:
    any of them
}