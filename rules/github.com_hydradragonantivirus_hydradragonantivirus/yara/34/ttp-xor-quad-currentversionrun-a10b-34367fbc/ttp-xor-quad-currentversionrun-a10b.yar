rule TTP_XOR_QUAD_CurrentVersionRun_a10b {
  strings:
    $key_a10b = { f2 64 [2] d6 6a [2] fd 46 [2] d3 64 [2] c7 7f [2] c8 65 [2] d6 78 [2] d4 79 [2] cf 7f [2] d3 78 [2] cf 57 }

  condition:
    any of them
}