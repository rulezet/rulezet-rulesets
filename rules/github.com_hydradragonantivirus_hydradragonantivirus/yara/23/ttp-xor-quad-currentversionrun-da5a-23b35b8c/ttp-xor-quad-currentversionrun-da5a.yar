rule TTP_XOR_QUAD_CurrentVersionRun_da5a {
  strings:
    $key_da5a = { 89 35 [2] ad 3b [2] 86 17 [2] a8 35 [2] bc 2e [2] b3 34 [2] ad 29 [2] af 28 [2] b4 2e [2] a8 29 [2] b4 06 }

  condition:
    any of them
}