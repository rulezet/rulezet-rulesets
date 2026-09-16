rule TTP_XOR_QUAD_CurrentVersionRun_da00 {
  strings:
    $key_da00 = { 89 6f [2] ad 61 [2] 86 4d [2] a8 6f [2] bc 74 [2] b3 6e [2] ad 73 [2] af 72 [2] b4 74 [2] a8 73 [2] b4 5c }

  condition:
    any of them
}