rule TTP_XOR_QUAD_CurrentVersionRun_a15a {
  strings:
    $key_a15a = { f2 35 [2] d6 3b [2] fd 17 [2] d3 35 [2] c7 2e [2] c8 34 [2] d6 29 [2] d4 28 [2] cf 2e [2] d3 29 [2] cf 06 }

  condition:
    any of them
}