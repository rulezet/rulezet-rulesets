rule TTP_XOR_QUAD_CurrentVersionRun_c962 {
  strings:
    $key_c962 = { 9a 0d [2] be 03 [2] 95 2f [2] bb 0d [2] af 16 [2] a0 0c [2] be 11 [2] bc 10 [2] a7 16 [2] bb 11 [2] a7 3e }

  condition:
    any of them
}