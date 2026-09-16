rule TTP_XOR_QUAD_CurrentVersionRun_a17a {
  strings:
    $key_a17a = { f2 15 [2] d6 1b [2] fd 37 [2] d3 15 [2] c7 0e [2] c8 14 [2] d6 09 [2] d4 08 [2] cf 0e [2] d3 09 [2] cf 26 }

  condition:
    any of them
}