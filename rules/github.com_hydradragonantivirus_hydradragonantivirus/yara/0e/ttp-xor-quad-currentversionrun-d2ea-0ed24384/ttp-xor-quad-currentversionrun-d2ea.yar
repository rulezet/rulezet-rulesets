rule TTP_XOR_QUAD_CurrentVersionRun_d2ea {
  strings:
    $key_d2ea = { 81 85 [2] a5 8b [2] 8e a7 [2] a0 85 [2] b4 9e [2] bb 84 [2] a5 99 [2] a7 98 [2] bc 9e [2] a0 99 [2] bc b6 }

  condition:
    any of them
}