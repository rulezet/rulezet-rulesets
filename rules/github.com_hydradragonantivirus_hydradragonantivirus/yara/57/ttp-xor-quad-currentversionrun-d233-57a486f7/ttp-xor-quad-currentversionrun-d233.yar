rule TTP_XOR_QUAD_CurrentVersionRun_d233 {
  strings:
    $key_d233 = { 81 5c [2] a5 52 [2] 8e 7e [2] a0 5c [2] b4 47 [2] bb 5d [2] a5 40 [2] a7 41 [2] bc 47 [2] a0 40 [2] bc 6f }

  condition:
    any of them
}