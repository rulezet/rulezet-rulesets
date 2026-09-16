rule TTP_XOR_QUAD_CurrentVersionRun_c9d7 {
  strings:
    $key_c9d7 = { 9a b8 [2] be b6 [2] 95 9a [2] bb b8 [2] af a3 [2] a0 b9 [2] be a4 [2] bc a5 [2] a7 a3 [2] bb a4 [2] a7 8b }

  condition:
    any of them
}