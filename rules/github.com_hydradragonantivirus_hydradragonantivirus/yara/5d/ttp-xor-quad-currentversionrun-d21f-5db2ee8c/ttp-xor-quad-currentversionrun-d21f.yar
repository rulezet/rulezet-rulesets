rule TTP_XOR_QUAD_CurrentVersionRun_d21f {
  strings:
    $key_d21f = { 81 70 [2] a5 7e [2] 8e 52 [2] a0 70 [2] b4 6b [2] bb 71 [2] a5 6c [2] a7 6d [2] bc 6b [2] a0 6c [2] bc 43 }

  condition:
    any of them
}