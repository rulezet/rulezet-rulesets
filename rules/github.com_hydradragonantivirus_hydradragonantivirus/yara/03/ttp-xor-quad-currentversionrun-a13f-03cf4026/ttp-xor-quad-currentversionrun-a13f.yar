rule TTP_XOR_QUAD_CurrentVersionRun_a13f {
  strings:
    $key_a13f = { f2 50 [2] d6 5e [2] fd 72 [2] d3 50 [2] c7 4b [2] c8 51 [2] d6 4c [2] d4 4d [2] cf 4b [2] d3 4c [2] cf 63 }

  condition:
    any of them
}