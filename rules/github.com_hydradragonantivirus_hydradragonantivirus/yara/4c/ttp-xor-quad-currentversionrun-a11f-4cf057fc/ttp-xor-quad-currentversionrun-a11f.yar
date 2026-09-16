rule TTP_XOR_QUAD_CurrentVersionRun_a11f {
  strings:
    $key_a11f = { f2 70 [2] d6 7e [2] fd 52 [2] d3 70 [2] c7 6b [2] c8 71 [2] d6 6c [2] d4 6d [2] cf 6b [2] d3 6c [2] cf 43 }

  condition:
    any of them
}