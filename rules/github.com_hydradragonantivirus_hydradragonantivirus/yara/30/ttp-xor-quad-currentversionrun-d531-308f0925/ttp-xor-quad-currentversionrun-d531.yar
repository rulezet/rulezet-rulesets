rule TTP_XOR_QUAD_CurrentVersionRun_d531 {
  strings:
    $key_d531 = { 86 5e [2] a2 50 [2] 89 7c [2] a7 5e [2] b3 45 [2] bc 5f [2] a2 42 [2] a0 43 [2] bb 45 [2] a7 42 [2] bb 6d }

  condition:
    any of them
}