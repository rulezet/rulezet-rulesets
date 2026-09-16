rule TTP_XOR_QUAD_CurrentVersionRun_a10d {
  strings:
    $key_a10d = { f2 62 [2] d6 6c [2] fd 40 [2] d3 62 [2] c7 79 [2] c8 63 [2] d6 7e [2] d4 7f [2] cf 79 [2] d3 7e [2] cf 51 }

  condition:
    any of them
}