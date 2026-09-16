rule TTP_XOR_QUAD_CurrentVersionRun_ce2f {
  strings:
    $key_ce2f = { 9d 40 [2] b9 4e [2] 92 62 [2] bc 40 [2] a8 5b [2] a7 41 [2] b9 5c [2] bb 5d [2] a0 5b [2] bc 5c [2] a0 73 }

  condition:
    any of them
}