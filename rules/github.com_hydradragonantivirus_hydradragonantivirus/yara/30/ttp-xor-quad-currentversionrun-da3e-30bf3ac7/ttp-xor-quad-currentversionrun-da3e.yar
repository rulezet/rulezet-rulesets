rule TTP_XOR_QUAD_CurrentVersionRun_da3e {
  strings:
    $key_da3e = { 89 51 [2] ad 5f [2] 86 73 [2] a8 51 [2] bc 4a [2] b3 50 [2] ad 4d [2] af 4c [2] b4 4a [2] a8 4d [2] b4 62 }

  condition:
    any of them
}