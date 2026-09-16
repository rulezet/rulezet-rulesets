rule TTP_XOR_QUAD_CurrentVersionRun_d52f {
  strings:
    $key_d52f = { 86 40 [2] a2 4e [2] 89 62 [2] a7 40 [2] b3 5b [2] bc 41 [2] a2 5c [2] a0 5d [2] bb 5b [2] a7 5c [2] bb 73 }

  condition:
    any of them
}