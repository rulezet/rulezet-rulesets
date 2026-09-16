rule TTP_XOR_QUAD_CurrentVersionRun_a6f2 {
  strings:
    $key_a6f2 = { f5 9d [2] d1 93 [2] fa bf [2] d4 9d [2] c0 86 [2] cf 9c [2] d1 81 [2] d3 80 [2] c8 86 [2] d4 81 [2] c8 ae }

  condition:
    any of them
}