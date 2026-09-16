rule TTP_XOR_QUAD_CurrentVersionRun_c9cd {
  strings:
    $key_c9cd = { 9a a2 [2] be ac [2] 95 80 [2] bb a2 [2] af b9 [2] a0 a3 [2] be be [2] bc bf [2] a7 b9 [2] bb be [2] a7 91 }

  condition:
    any of them
}