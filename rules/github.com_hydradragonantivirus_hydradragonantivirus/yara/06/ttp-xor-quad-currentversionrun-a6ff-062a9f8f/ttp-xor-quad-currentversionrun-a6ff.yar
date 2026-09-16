rule TTP_XOR_QUAD_CurrentVersionRun_a6ff {
  strings:
    $key_a6ff = { f5 90 [2] d1 9e [2] fa b2 [2] d4 90 [2] c0 8b [2] cf 91 [2] d1 8c [2] d3 8d [2] c8 8b [2] d4 8c [2] c8 a3 }

  condition:
    any of them
}