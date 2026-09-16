rule TTP_XOR_QUAD_CurrentVersionRun_a110 {
  strings:
    $key_a110 = { f2 7f [2] d6 71 [2] fd 5d [2] d3 7f [2] c7 64 [2] c8 7e [2] d6 63 [2] d4 62 [2] cf 64 [2] d3 63 [2] cf 4c }

  condition:
    any of them
}