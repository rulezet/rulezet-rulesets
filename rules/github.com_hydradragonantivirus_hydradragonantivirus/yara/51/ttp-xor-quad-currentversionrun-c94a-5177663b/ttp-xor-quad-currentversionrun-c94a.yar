rule TTP_XOR_QUAD_CurrentVersionRun_c94a {
  strings:
    $key_c94a = { 9a 25 [2] be 2b [2] 95 07 [2] bb 25 [2] af 3e [2] a0 24 [2] be 39 [2] bc 38 [2] a7 3e [2] bb 39 [2] a7 16 }

  condition:
    any of them
}