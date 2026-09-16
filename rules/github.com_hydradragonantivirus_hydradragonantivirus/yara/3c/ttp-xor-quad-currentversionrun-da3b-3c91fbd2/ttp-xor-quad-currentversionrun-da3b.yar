rule TTP_XOR_QUAD_CurrentVersionRun_da3b {
  strings:
    $key_da3b = { 89 54 [2] ad 5a [2] 86 76 [2] a8 54 [2] bc 4f [2] b3 55 [2] ad 48 [2] af 49 [2] b4 4f [2] a8 48 [2] b4 67 }

  condition:
    any of them
}