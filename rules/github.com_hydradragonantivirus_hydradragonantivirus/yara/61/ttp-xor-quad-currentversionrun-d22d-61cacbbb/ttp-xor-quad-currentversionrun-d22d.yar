rule TTP_XOR_QUAD_CurrentVersionRun_d22d {
  strings:
    $key_d22d = { 81 42 [2] a5 4c [2] 8e 60 [2] a0 42 [2] b4 59 [2] bb 43 [2] a5 5e [2] a7 5f [2] bc 59 [2] a0 5e [2] bc 71 }

  condition:
    any of them
}