rule TTP_XOR_QUAD_CurrentVersionRun_cee2 {
  strings:
    $key_cee2 = { 9d 8d [2] b9 83 [2] 92 af [2] bc 8d [2] a8 96 [2] a7 8c [2] b9 91 [2] bb 90 [2] a0 96 [2] bc 91 [2] a0 be }

  condition:
    any of them
}