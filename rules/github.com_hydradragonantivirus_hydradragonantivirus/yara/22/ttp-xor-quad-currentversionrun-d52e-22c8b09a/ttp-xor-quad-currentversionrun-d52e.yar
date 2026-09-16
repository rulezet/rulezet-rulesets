rule TTP_XOR_QUAD_CurrentVersionRun_d52e {
  strings:
    $key_d52e = { 86 41 [2] a2 4f [2] 89 63 [2] a7 41 [2] b3 5a [2] bc 40 [2] a2 5d [2] a0 5c [2] bb 5a [2] a7 5d [2] bb 72 }

  condition:
    any of them
}