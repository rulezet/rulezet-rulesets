rule TTP_XOR_QUAD_CurrentVersionRun_d20c {
  strings:
    $key_d20c = { 81 63 [2] a5 6d [2] 8e 41 [2] a0 63 [2] b4 78 [2] bb 62 [2] a5 7f [2] a7 7e [2] bc 78 [2] a0 7f [2] bc 50 }

  condition:
    any of them
}