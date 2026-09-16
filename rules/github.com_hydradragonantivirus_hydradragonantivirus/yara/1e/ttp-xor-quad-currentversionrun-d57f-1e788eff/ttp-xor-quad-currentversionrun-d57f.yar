rule TTP_XOR_QUAD_CurrentVersionRun_d57f {
  strings:
    $key_d57f = { 86 10 [2] a2 1e [2] 89 32 [2] a7 10 [2] b3 0b [2] bc 11 [2] a2 0c [2] a0 0d [2] bb 0b [2] a7 0c [2] bb 23 }

  condition:
    any of them
}