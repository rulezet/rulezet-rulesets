rule TTP_XOR_QUAD_CurrentVersionRun_d53d {
  strings:
    $key_d53d = { 86 52 [2] a2 5c [2] 89 70 [2] a7 52 [2] b3 49 [2] bc 53 [2] a2 4e [2] a0 4f [2] bb 49 [2] a7 4e [2] bb 61 }

  condition:
    any of them
}