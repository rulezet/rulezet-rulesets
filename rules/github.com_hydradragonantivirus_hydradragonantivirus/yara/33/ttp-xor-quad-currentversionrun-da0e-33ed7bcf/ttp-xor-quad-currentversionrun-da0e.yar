rule TTP_XOR_QUAD_CurrentVersionRun_da0e {
  strings:
    $key_da0e = { 89 61 [2] ad 6f [2] 86 43 [2] a8 61 [2] bc 7a [2] b3 60 [2] ad 7d [2] af 7c [2] b4 7a [2] a8 7d [2] b4 52 }

  condition:
    any of them
}