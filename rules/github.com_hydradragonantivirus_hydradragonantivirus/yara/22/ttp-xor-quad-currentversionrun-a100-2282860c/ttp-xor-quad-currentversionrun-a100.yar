rule TTP_XOR_QUAD_CurrentVersionRun_a100 {
  strings:
    $key_a100 = { f2 6f [2] d6 61 [2] fd 4d [2] d3 6f [2] c7 74 [2] c8 6e [2] d6 73 [2] d4 72 [2] cf 74 [2] d3 73 [2] cf 5c }

  condition:
    any of them
}