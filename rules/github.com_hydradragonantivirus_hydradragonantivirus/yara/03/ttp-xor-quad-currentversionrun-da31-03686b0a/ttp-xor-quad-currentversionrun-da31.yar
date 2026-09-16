rule TTP_XOR_QUAD_CurrentVersionRun_da31 {
  strings:
    $key_da31 = { 89 5e [2] ad 50 [2] 86 7c [2] a8 5e [2] bc 45 [2] b3 5f [2] ad 42 [2] af 43 [2] b4 45 [2] a8 42 [2] b4 6d }

  condition:
    any of them
}