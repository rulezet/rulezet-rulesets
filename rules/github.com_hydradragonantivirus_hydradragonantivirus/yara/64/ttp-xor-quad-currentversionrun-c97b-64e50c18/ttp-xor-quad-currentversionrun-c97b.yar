rule TTP_XOR_QUAD_CurrentVersionRun_c97b {
  strings:
    $key_c97b = { 9a 14 [2] be 1a [2] 95 36 [2] bb 14 [2] af 0f [2] a0 15 [2] be 08 [2] bc 09 [2] a7 0f [2] bb 08 [2] a7 27 }

  condition:
    any of them
}