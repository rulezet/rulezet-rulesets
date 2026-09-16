rule TTP_XOR_QUAD_CurrentVersionRun_d23a {
  strings:
    $key_d23a = { 81 55 [2] a5 5b [2] 8e 77 [2] a0 55 [2] b4 4e [2] bb 54 [2] a5 49 [2] a7 48 [2] bc 4e [2] a0 49 [2] bc 66 }

  condition:
    any of them
}