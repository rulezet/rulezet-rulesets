rule TTP_XOR_QUAD_CurrentVersionRun_d510 {
  strings:
    $key_d510 = { 86 7f [2] a2 71 [2] 89 5d [2] a7 7f [2] b3 64 [2] bc 7e [2] a2 63 [2] a0 62 [2] bb 64 [2] a7 63 [2] bb 4c }

  condition:
    any of them
}