rule TTP_XOR_QUAD_CurrentVersionRun_a109 {
  strings:
    $key_a109 = { f2 66 [2] d6 68 [2] fd 44 [2] d3 66 [2] c7 7d [2] c8 67 [2] d6 7a [2] d4 7b [2] cf 7d [2] d3 7a [2] cf 55 }

  condition:
    any of them
}