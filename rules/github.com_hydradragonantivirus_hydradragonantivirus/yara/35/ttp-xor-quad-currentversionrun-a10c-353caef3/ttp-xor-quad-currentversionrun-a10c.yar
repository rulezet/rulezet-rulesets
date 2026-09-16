rule TTP_XOR_QUAD_CurrentVersionRun_a10c {
  strings:
    $key_a10c = { f2 63 [2] d6 6d [2] fd 41 [2] d3 63 [2] c7 78 [2] c8 62 [2] d6 7f [2] d4 7e [2] cf 78 [2] d3 7f [2] cf 50 }

  condition:
    any of them
}