rule TTP_XOR_QUAD_CurrentVersionRun_c96f {
  strings:
    $key_c96f = { 9a 00 [2] be 0e [2] 95 22 [2] bb 00 [2] af 1b [2] a0 01 [2] be 1c [2] bc 1d [2] a7 1b [2] bb 1c [2] a7 33 }

  condition:
    any of them
}