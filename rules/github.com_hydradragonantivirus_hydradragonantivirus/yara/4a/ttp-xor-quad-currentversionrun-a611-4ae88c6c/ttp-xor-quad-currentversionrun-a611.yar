rule TTP_XOR_QUAD_CurrentVersionRun_a611 {
  strings:
    $key_a611 = { f5 7e [2] d1 70 [2] fa 5c [2] d4 7e [2] c0 65 [2] cf 7f [2] d1 62 [2] d3 63 [2] c8 65 [2] d4 62 [2] c8 4d }

  condition:
    any of them
}