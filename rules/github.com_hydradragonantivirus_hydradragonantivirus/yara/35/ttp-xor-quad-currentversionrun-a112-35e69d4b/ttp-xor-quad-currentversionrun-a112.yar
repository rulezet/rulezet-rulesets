rule TTP_XOR_QUAD_CurrentVersionRun_a112 {
  strings:
    $key_a112 = { f2 7d [2] d6 73 [2] fd 5f [2] d3 7d [2] c7 66 [2] c8 7c [2] d6 61 [2] d4 60 [2] cf 66 [2] d3 61 [2] cf 4e }

  condition:
    any of them
}