rule TTP_XOR_QUAD_CurrentVersionRun_a61e {
  strings:
    $key_a61e = { f5 71 [2] d1 7f [2] fa 53 [2] d4 71 [2] c0 6a [2] cf 70 [2] d1 6d [2] d3 6c [2] c8 6a [2] d4 6d [2] c8 42 }

  condition:
    any of them
}