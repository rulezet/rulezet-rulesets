rule TTP_XOR_QUAD_CurrentVersionRun_a603 {
  strings:
    $key_a603 = { f5 6c [2] d1 62 [2] fa 4e [2] d4 6c [2] c0 77 [2] cf 6d [2] d1 70 [2] d3 71 [2] c8 77 [2] d4 70 [2] c8 5f }

  condition:
    any of them
}