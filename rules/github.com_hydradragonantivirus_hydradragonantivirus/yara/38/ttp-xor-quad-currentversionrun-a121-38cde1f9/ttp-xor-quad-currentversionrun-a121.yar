rule TTP_XOR_QUAD_CurrentVersionRun_a121 {
  strings:
    $key_a121 = { f2 4e [2] d6 40 [2] fd 6c [2] d3 4e [2] c7 55 [2] c8 4f [2] d6 52 [2] d4 53 [2] cf 55 [2] d3 52 [2] cf 7d }

  condition:
    any of them
}