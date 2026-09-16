rule TTP_XOR_QUAD_CurrentVersionRun_d2fa {
  strings:
    $key_d2fa = { 81 95 [2] a5 9b [2] 8e b7 [2] a0 95 [2] b4 8e [2] bb 94 [2] a5 89 [2] a7 88 [2] bc 8e [2] a0 89 [2] bc a6 }

  condition:
    any of them
}