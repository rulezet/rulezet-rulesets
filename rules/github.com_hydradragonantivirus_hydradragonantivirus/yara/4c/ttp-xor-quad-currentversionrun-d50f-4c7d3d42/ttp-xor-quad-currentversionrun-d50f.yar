rule TTP_XOR_QUAD_CurrentVersionRun_d50f {
  strings:
    $key_d50f = { 86 60 [2] a2 6e [2] 89 42 [2] a7 60 [2] b3 7b [2] bc 61 [2] a2 7c [2] a0 7d [2] bb 7b [2] a7 7c [2] bb 53 }

  condition:
    any of them
}