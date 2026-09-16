rule TTP_XOR_QUAD_CurrentVersionRun_c9ff {
  strings:
    $key_c9ff = { 9a 90 [2] be 9e [2] 95 b2 [2] bb 90 [2] af 8b [2] a0 91 [2] be 8c [2] bc 8d [2] a7 8b [2] bb 8c [2] a7 a3 }

  condition:
    any of them
}