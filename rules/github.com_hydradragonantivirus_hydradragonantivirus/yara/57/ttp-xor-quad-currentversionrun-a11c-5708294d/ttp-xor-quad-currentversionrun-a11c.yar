rule TTP_XOR_QUAD_CurrentVersionRun_a11c {
  strings:
    $key_a11c = { f2 73 [2] d6 7d [2] fd 51 [2] d3 73 [2] c7 68 [2] c8 72 [2] d6 6f [2] d4 6e [2] cf 68 [2] d3 6f [2] cf 40 }

  condition:
    any of them
}