rule TTP_XOR_QUAD_CurrentVersionRun_c917 {
  strings:
    $key_c917 = { 9a 78 [2] be 76 [2] 95 5a [2] bb 78 [2] af 63 [2] a0 79 [2] be 64 [2] bc 65 [2] a7 63 [2] bb 64 [2] a7 4b }

  condition:
    any of them
}