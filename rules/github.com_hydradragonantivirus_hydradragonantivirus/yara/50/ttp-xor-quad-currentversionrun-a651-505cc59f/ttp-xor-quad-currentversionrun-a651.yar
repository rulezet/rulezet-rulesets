rule TTP_XOR_QUAD_CurrentVersionRun_a651 {
  strings:
    $key_a651 = { f5 3e [2] d1 30 [2] fa 1c [2] d4 3e [2] c0 25 [2] cf 3f [2] d1 22 [2] d3 23 [2] c8 25 [2] d4 22 [2] c8 0d }

  condition:
    any of them
}