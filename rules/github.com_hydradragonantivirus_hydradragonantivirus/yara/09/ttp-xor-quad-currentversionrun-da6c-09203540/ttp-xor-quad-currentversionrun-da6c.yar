rule TTP_XOR_QUAD_CurrentVersionRun_da6c {
  strings:
    $key_da6c = { 89 03 [2] ad 0d [2] 86 21 [2] a8 03 [2] bc 18 [2] b3 02 [2] ad 1f [2] af 1e [2] b4 18 [2] a8 1f [2] b4 30 }

  condition:
    any of them
}