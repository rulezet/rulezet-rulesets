rule TTP_XOR_QUAD_CurrentVersionRun_da4a {
  strings:
    $key_da4a = { 89 25 [2] ad 2b [2] 86 07 [2] a8 25 [2] bc 3e [2] b3 24 [2] ad 39 [2] af 38 [2] b4 3e [2] a8 39 [2] b4 16 }

  condition:
    any of them
}