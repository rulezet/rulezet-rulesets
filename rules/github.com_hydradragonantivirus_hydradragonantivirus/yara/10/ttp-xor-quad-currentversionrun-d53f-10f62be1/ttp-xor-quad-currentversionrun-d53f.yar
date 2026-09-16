rule TTP_XOR_QUAD_CurrentVersionRun_d53f {
  strings:
    $key_d53f = { 86 50 [2] a2 5e [2] 89 72 [2] a7 50 [2] b3 4b [2] bc 51 [2] a2 4c [2] a0 4d [2] bb 4b [2] a7 4c [2] bb 63 }

  condition:
    any of them
}