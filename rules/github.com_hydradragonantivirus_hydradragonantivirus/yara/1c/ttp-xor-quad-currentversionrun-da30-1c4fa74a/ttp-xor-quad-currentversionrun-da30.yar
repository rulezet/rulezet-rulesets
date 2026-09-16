rule TTP_XOR_QUAD_CurrentVersionRun_da30 {
  strings:
    $key_da30 = { 89 5f [2] ad 51 [2] 86 7d [2] a8 5f [2] bc 44 [2] b3 5e [2] ad 43 [2] af 42 [2] b4 44 [2] a8 43 [2] b4 6c }

  condition:
    any of them
}