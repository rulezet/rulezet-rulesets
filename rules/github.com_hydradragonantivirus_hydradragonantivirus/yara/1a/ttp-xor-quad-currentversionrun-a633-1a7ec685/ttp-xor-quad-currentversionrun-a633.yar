rule TTP_XOR_QUAD_CurrentVersionRun_a633 {
  strings:
    $key_a633 = { f5 5c [2] d1 52 [2] fa 7e [2] d4 5c [2] c0 47 [2] cf 5d [2] d1 40 [2] d3 41 [2] c8 47 [2] d4 40 [2] c8 6f }

  condition:
    any of them
}