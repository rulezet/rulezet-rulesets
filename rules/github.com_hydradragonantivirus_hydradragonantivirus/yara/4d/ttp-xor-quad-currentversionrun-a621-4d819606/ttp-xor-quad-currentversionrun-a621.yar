rule TTP_XOR_QUAD_CurrentVersionRun_a621 {
  strings:
    $key_a621 = { f5 4e [2] d1 40 [2] fa 6c [2] d4 4e [2] c0 55 [2] cf 4f [2] d1 52 [2] d3 53 [2] c8 55 [2] d4 52 [2] c8 7d }

  condition:
    any of them
}