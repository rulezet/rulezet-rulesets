rule TTP_XOR_QUAD_CurrentVersionRun_a671 {
  strings:
    $key_a671 = { f5 1e [2] d1 10 [2] fa 3c [2] d4 1e [2] c0 05 [2] cf 1f [2] d1 02 [2] d3 03 [2] c8 05 [2] d4 02 [2] c8 2d }

  condition:
    any of them
}