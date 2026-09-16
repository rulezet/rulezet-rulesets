rule TTP_XOR_QUAD_CurrentVersionRun_a10a {
  strings:
    $key_a10a = { f2 65 [2] d6 6b [2] fd 47 [2] d3 65 [2] c7 7e [2] c8 64 [2] d6 79 [2] d4 78 [2] cf 7e [2] d3 79 [2] cf 56 }

  condition:
    any of them
}