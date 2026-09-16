rule TTP_XOR_QUAD_CurrentVersionRun_c975 {
  strings:
    $key_c975 = { 9a 1a [2] be 14 [2] 95 38 [2] bb 1a [2] af 01 [2] a0 1b [2] be 06 [2] bc 07 [2] a7 01 [2] bb 06 [2] a7 29 }

  condition:
    any of them
}