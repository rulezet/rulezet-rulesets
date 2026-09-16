rule TTP_XOR_QUAD_CurrentVersionRun_d221 {
  strings:
    $key_d221 = { 81 4e [2] a5 40 [2] 8e 6c [2] a0 4e [2] b4 55 [2] bb 4f [2] a5 52 [2] a7 53 [2] bc 55 [2] a0 52 [2] bc 7d }

  condition:
    any of them
}