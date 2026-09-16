rule TTP_XOR_QUAD_CurrentVersionRun_a11e {
  strings:
    $key_a11e = { f2 71 [2] d6 7f [2] fd 53 [2] d3 71 [2] c7 6a [2] c8 70 [2] d6 6d [2] d4 6c [2] cf 6a [2] d3 6d [2] cf 42 }

  condition:
    any of them
}