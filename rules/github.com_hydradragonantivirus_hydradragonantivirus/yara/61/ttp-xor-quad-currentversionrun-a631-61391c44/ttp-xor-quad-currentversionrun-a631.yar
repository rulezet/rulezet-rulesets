rule TTP_XOR_QUAD_CurrentVersionRun_a631 {
  strings:
    $key_a631 = { f5 5e [2] d1 50 [2] fa 7c [2] d4 5e [2] c0 45 [2] cf 5f [2] d1 42 [2] d3 43 [2] c8 45 [2] d4 42 [2] c8 6d }

  condition:
    any of them
}