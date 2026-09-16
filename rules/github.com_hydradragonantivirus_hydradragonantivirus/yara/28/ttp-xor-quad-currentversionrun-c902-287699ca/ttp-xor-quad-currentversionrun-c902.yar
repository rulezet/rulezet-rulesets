rule TTP_XOR_QUAD_CurrentVersionRun_c902 {
  strings:
    $key_c902 = { 9a 6d [2] be 63 [2] 95 4f [2] bb 6d [2] af 76 [2] a0 6c [2] be 71 [2] bc 70 [2] a7 76 [2] bb 71 [2] a7 5e }

  condition:
    any of them
}