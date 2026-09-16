rule TTP_XOR_QUAD_CurrentVersionRun_a63b {
  strings:
    $key_a63b = { f5 54 [2] d1 5a [2] fa 76 [2] d4 54 [2] c0 4f [2] cf 55 [2] d1 48 [2] d3 49 [2] c8 4f [2] d4 48 [2] c8 67 }

  condition:
    any of them
}