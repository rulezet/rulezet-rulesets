rule TTP_XOR_QUAD_CurrentVersionRun_da6d {
  strings:
    $key_da6d = { 89 02 [2] ad 0c [2] 86 20 [2] a8 02 [2] bc 19 [2] b3 03 [2] ad 1e [2] af 1f [2] b4 19 [2] a8 1e [2] b4 31 }

  condition:
    any of them
}