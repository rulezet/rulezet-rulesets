rule TTP_XOR_QUAD_CurrentVersionRun_d51f {
  strings:
    $key_d51f = { 86 70 [2] a2 7e [2] 89 52 [2] a7 70 [2] b3 6b [2] bc 71 [2] a2 6c [2] a0 6d [2] bb 6b [2] a7 6c [2] bb 43 }

  condition:
    any of them
}