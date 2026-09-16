rule TTP_XOR_QUAD_CurrentVersionRun_c9dd {
  strings:
    $key_c9dd = { 9a b2 [2] be bc [2] 95 90 [2] bb b2 [2] af a9 [2] a0 b3 [2] be ae [2] bc af [2] a7 a9 [2] bb ae [2] a7 81 }

  condition:
    any of them
}