rule TTP_XOR_QUAD_CurrentVersionRun_a63f {
  strings:
    $key_a63f = { f5 50 [2] d1 5e [2] fa 72 [2] d4 50 [2] c0 4b [2] cf 51 [2] d1 4c [2] d3 4d [2] c8 4b [2] d4 4c [2] c8 63 }

  condition:
    any of them
}