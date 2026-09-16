rule TTP_XOR_QUAD_CurrentVersionRun_a66b {
  strings:
    $key_a66b = { f5 04 [2] d1 0a [2] fa 26 [2] d4 04 [2] c0 1f [2] cf 05 [2] d1 18 [2] d3 19 [2] c8 1f [2] d4 18 [2] c8 37 }

  condition:
    any of them
}