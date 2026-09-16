rule TTP_XOR_QUAD_CurrentVersionRun_d24a {
  strings:
    $key_d24a = { 81 25 [2] a5 2b [2] 8e 07 [2] a0 25 [2] b4 3e [2] bb 24 [2] a5 39 [2] a7 38 [2] bc 3e [2] a0 39 [2] bc 16 }

  condition:
    any of them
}