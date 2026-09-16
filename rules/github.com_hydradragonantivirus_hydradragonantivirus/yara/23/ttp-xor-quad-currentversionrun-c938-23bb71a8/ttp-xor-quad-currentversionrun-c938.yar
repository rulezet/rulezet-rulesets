rule TTP_XOR_QUAD_CurrentVersionRun_c938 {
  strings:
    $key_c938 = { 9a 57 [2] be 59 [2] 95 75 [2] bb 57 [2] af 4c [2] a0 56 [2] be 4b [2] bc 4a [2] a7 4c [2] bb 4b [2] a7 64 }

  condition:
    any of them
}