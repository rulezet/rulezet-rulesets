rule TTP_XOR_QUAD_CurrentVersionRun_d23d {
  strings:
    $key_d23d = { 81 52 [2] a5 5c [2] 8e 70 [2] a0 52 [2] b4 49 [2] bb 53 [2] a5 4e [2] a7 4f [2] bc 49 [2] a0 4e [2] bc 61 }

  condition:
    any of them
}