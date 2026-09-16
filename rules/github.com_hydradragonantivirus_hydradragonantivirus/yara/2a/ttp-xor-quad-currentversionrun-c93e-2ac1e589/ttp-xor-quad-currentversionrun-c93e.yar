rule TTP_XOR_QUAD_CurrentVersionRun_c93e {
  strings:
    $key_c93e = { 9a 51 [2] be 5f [2] 95 73 [2] bb 51 [2] af 4a [2] a0 50 [2] be 4d [2] bc 4c [2] a7 4a [2] bb 4d [2] a7 62 }

  condition:
    any of them
}