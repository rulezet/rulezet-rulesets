rule TTP_XOR_QUAD_CurrentVersionRun_c9dc {
  strings:
    $key_c9dc = { 9a b3 [2] be bd [2] 95 91 [2] bb b3 [2] af a8 [2] a0 b2 [2] be af [2] bc ae [2] a7 a8 [2] bb af [2] a7 80 }

  condition:
    any of them
}