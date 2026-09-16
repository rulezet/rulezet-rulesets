rule TTP_XOR_QUAD_CurrentVersionRun_a60a {
  strings:
    $key_a60a = { f5 65 [2] d1 6b [2] fa 47 [2] d4 65 [2] c0 7e [2] cf 64 [2] d1 79 [2] d3 78 [2] c8 7e [2] d4 79 [2] c8 56 }

  condition:
    any of them
}