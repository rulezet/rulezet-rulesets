rule TTP_XOR_QUAD_CurrentVersionRun_d5ea {
  strings:
    $key_d5ea = { 86 85 [2] a2 8b [2] 89 a7 [2] a7 85 [2] b3 9e [2] bc 84 [2] a2 99 [2] a0 98 [2] bb 9e [2] a7 99 [2] bb b6 }

  condition:
    any of them
}