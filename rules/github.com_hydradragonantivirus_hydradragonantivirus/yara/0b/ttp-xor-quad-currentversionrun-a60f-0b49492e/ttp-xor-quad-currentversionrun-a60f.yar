rule TTP_XOR_QUAD_CurrentVersionRun_a60f {
  strings:
    $key_a60f = { f5 60 [2] d1 6e [2] fa 42 [2] d4 60 [2] c0 7b [2] cf 61 [2] d1 7c [2] d3 7d [2] c8 7b [2] d4 7c [2] c8 53 }

  condition:
    any of them
}