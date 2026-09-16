rule TTP_XOR_QUAD_CurrentVersionRun_d2ee {
  strings:
    $key_d2ee = { 81 81 [2] a5 8f [2] 8e a3 [2] a0 81 [2] b4 9a [2] bb 80 [2] a5 9d [2] a7 9c [2] bc 9a [2] a0 9d [2] bc b2 }

  condition:
    any of them
}