rule TTP_XOR_QUAD_CurrentVersionRun_d54a {
  strings:
    $key_d54a = { 86 25 [2] a2 2b [2] 89 07 [2] a7 25 [2] b3 3e [2] bc 24 [2] a2 39 [2] a0 38 [2] bb 3e [2] a7 39 [2] bb 16 }

  condition:
    any of them
}