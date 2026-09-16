rule TTP_XOR_QUAD_CurrentVersionRun_c97e {
  strings:
    $key_c97e = { 9a 11 [2] be 1f [2] 95 33 [2] bb 11 [2] af 0a [2] a0 10 [2] be 0d [2] bc 0c [2] a7 0a [2] bb 0d [2] a7 22 }

  condition:
    any of them
}