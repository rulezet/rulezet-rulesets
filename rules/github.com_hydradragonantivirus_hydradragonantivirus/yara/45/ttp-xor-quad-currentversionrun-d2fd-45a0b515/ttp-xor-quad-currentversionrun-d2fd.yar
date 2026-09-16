rule TTP_XOR_QUAD_CurrentVersionRun_d2fd {
  strings:
    $key_d2fd = { 81 92 [2] a5 9c [2] 8e b0 [2] a0 92 [2] b4 89 [2] bb 93 [2] a5 8e [2] a7 8f [2] bc 89 [2] a0 8e [2] bc a1 }

  condition:
    any of them
}