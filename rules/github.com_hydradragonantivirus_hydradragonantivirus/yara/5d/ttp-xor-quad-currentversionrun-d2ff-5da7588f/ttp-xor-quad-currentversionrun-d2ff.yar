rule TTP_XOR_QUAD_CurrentVersionRun_d2ff {
  strings:
    $key_d2ff = { 81 90 [2] a5 9e [2] 8e b2 [2] a0 90 [2] b4 8b [2] bb 91 [2] a5 8c [2] a7 8d [2] bc 8b [2] a0 8c [2] bc a3 }

  condition:
    any of them
}