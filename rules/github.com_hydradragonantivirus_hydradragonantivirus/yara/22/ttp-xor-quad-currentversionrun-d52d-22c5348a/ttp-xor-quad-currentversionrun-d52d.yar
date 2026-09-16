rule TTP_XOR_QUAD_CurrentVersionRun_d52d {
  strings:
    $key_d52d = { 86 42 [2] a2 4c [2] 89 60 [2] a7 42 [2] b3 59 [2] bc 43 [2] a2 5e [2] a0 5f [2] bb 59 [2] a7 5e [2] bb 71 }

  condition:
    any of them
}