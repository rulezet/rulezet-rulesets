rule TTP_XOR_QUAD_CurrentVersionRun_d5f0 {
  strings:
    $key_d5f0 = { 86 9f [2] a2 91 [2] 89 bd [2] a7 9f [2] b3 84 [2] bc 9e [2] a2 83 [2] a0 82 [2] bb 84 [2] a7 83 [2] bb ac }

  condition:
    any of them
}