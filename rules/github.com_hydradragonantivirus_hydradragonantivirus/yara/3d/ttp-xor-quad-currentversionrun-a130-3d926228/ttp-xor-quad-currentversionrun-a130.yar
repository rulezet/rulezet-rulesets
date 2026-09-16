rule TTP_XOR_QUAD_CurrentVersionRun_a130 {
  strings:
    $key_a130 = { f2 5f [2] d6 51 [2] fd 7d [2] d3 5f [2] c7 44 [2] c8 5e [2] d6 43 [2] d4 42 [2] cf 44 [2] d3 43 [2] cf 6c }

  condition:
    any of them
}