rule TTP_XOR_QUAD_CurrentVersionRun_a13c {
  strings:
    $key_a13c = { f2 53 [2] d6 5d [2] fd 71 [2] d3 53 [2] c7 48 [2] c8 52 [2] d6 4f [2] d4 4e [2] cf 48 [2] d3 4f [2] cf 60 }

  condition:
    any of them
}