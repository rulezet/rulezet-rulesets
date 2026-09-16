rule TTP_XOR_QUAD_CurrentVersionRun_a61d {
  strings:
    $key_a61d = { f5 72 [2] d1 7c [2] fa 50 [2] d4 72 [2] c0 69 [2] cf 73 [2] d1 6e [2] d3 6f [2] c8 69 [2] d4 6e [2] c8 41 }

  condition:
    any of them
}