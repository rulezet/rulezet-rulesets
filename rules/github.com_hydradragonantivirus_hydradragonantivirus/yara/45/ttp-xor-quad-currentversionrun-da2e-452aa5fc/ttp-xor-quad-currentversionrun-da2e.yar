rule TTP_XOR_QUAD_CurrentVersionRun_da2e {
  strings:
    $key_da2e = { 89 41 [2] ad 4f [2] 86 63 [2] a8 41 [2] bc 5a [2] b3 40 [2] ad 5d [2] af 5c [2] b4 5a [2] a8 5d [2] b4 72 }

  condition:
    any of them
}