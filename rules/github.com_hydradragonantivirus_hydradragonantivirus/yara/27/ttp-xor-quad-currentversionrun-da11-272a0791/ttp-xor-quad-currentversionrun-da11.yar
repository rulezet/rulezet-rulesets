rule TTP_XOR_QUAD_CurrentVersionRun_da11 {
  strings:
    $key_da11 = { 89 7e [2] ad 70 [2] 86 5c [2] a8 7e [2] bc 65 [2] b3 7f [2] ad 62 [2] af 63 [2] b4 65 [2] a8 62 [2] b4 4d }

  condition:
    any of them
}