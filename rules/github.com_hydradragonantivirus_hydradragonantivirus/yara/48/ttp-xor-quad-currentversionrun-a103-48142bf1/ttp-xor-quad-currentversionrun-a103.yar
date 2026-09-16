rule TTP_XOR_QUAD_CurrentVersionRun_a103 {
  strings:
    $key_a103 = { f2 6c [2] d6 62 [2] fd 4e [2] d3 6c [2] c7 77 [2] c8 6d [2] d6 70 [2] d4 71 [2] cf 77 [2] d3 70 [2] cf 5f }

  condition:
    any of them
}