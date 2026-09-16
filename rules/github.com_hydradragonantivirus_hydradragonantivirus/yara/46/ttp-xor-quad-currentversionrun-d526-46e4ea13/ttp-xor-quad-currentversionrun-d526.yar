rule TTP_XOR_QUAD_CurrentVersionRun_d526 {
  strings:
    $key_d526 = { 86 49 [2] a2 47 [2] 89 6b [2] a7 49 [2] b3 52 [2] bc 48 [2] a2 55 [2] a0 54 [2] bb 52 [2] a7 55 [2] bb 7a }

  condition:
    any of them
}