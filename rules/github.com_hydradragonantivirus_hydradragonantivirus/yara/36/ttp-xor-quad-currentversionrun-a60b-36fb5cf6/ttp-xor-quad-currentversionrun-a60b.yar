rule TTP_XOR_QUAD_CurrentVersionRun_a60b {
  strings:
    $key_a60b = { f5 64 [2] d1 6a [2] fa 46 [2] d4 64 [2] c0 7f [2] cf 65 [2] d1 78 [2] d3 79 [2] c8 7f [2] d4 78 [2] c8 57 }

  condition:
    any of them
}