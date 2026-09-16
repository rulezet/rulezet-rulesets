rule TTP_XOR_QUAD_CurrentVersionRun_a60d {
  strings:
    $key_a60d = { f5 62 [2] d1 6c [2] fa 40 [2] d4 62 [2] c0 79 [2] cf 63 [2] d1 7e [2] d3 7f [2] c8 79 [2] d4 7e [2] c8 51 }

  condition:
    any of them
}