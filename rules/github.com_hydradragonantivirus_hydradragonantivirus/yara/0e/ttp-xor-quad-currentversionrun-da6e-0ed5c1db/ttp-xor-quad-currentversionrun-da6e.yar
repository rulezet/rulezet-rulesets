rule TTP_XOR_QUAD_CurrentVersionRun_da6e {
  strings:
    $key_da6e = { 89 01 [2] ad 0f [2] 86 23 [2] a8 01 [2] bc 1a [2] b3 00 [2] ad 1d [2] af 1c [2] b4 1a [2] a8 1d [2] b4 32 }

  condition:
    any of them
}