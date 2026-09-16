rule TTP_XOR_QUAD_CurrentVersionRun_daea {
  strings:
    $key_daea = { 89 85 [2] ad 8b [2] 86 a7 [2] a8 85 [2] bc 9e [2] b3 84 [2] ad 99 [2] af 98 [2] b4 9e [2] a8 99 [2] b4 b6 }

  condition:
    any of them
}