rule TTP_XOR_QUAD_CurrentVersionRun_a10e {
  strings:
    $key_a10e = { f2 61 [2] d6 6f [2] fd 43 [2] d3 61 [2] c7 7a [2] c8 60 [2] d6 7d [2] d4 7c [2] cf 7a [2] d3 7d [2] cf 52 }

  condition:
    any of them
}