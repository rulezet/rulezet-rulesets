rule TTP_XOR_QUAD_CurrentVersionRun_c9d0 {
  strings:
    $key_c9d0 = { 9a bf [2] be b1 [2] 95 9d [2] bb bf [2] af a4 [2] a0 be [2] be a3 [2] bc a2 [2] a7 a4 [2] bb a3 [2] a7 8c }

  condition:
    any of them
}