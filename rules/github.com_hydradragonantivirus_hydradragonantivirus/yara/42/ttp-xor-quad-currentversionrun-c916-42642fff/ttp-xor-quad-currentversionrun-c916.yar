rule TTP_XOR_QUAD_CurrentVersionRun_c916 {
  strings:
    $key_c916 = { 9a 79 [2] be 77 [2] 95 5b [2] bb 79 [2] af 62 [2] a0 78 [2] be 65 [2] bc 64 [2] a7 62 [2] bb 65 [2] a7 4a }

  condition:
    any of them
}