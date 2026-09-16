rule TTP_XOR_QUAD_CurrentVersionRun_a162 {
  strings:
    $key_a162 = { f2 0d [2] d6 03 [2] fd 2f [2] d3 0d [2] c7 16 [2] c8 0c [2] d6 11 [2] d4 10 [2] cf 16 [2] d3 11 [2] cf 3e }

  condition:
    any of them
}