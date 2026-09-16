rule TTP_XOR_QUAD_CurrentVersionRun_a670 {
  strings:
    $key_a670 = { f5 1f [2] d1 11 [2] fa 3d [2] d4 1f [2] c0 04 [2] cf 1e [2] d1 03 [2] d3 02 [2] c8 04 [2] d4 03 [2] c8 2c }

  condition:
    any of them
}