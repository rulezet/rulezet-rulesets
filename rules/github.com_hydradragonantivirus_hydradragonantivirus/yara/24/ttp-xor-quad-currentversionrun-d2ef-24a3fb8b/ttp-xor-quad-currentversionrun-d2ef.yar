rule TTP_XOR_QUAD_CurrentVersionRun_d2ef {
  strings:
    $key_d2ef = { 81 80 [2] a5 8e [2] 8e a2 [2] a0 80 [2] b4 9b [2] bb 81 [2] a5 9c [2] a7 9d [2] bc 9b [2] a0 9c [2] bc b3 }

  condition:
    any of them
}