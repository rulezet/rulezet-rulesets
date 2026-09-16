rule TTP_XOR_QUAD_CurrentVersionRun_da3a {
  strings:
    $key_da3a = { 89 55 [2] ad 5b [2] 86 77 [2] a8 55 [2] bc 4e [2] b3 54 [2] ad 49 [2] af 48 [2] b4 4e [2] a8 49 [2] b4 66 }

  condition:
    any of them
}