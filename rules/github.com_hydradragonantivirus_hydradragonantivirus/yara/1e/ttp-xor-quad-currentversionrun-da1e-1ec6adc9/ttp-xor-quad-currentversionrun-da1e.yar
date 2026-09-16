rule TTP_XOR_QUAD_CurrentVersionRun_da1e {
  strings:
    $key_da1e = { 89 71 [2] ad 7f [2] 86 53 [2] a8 71 [2] bc 6a [2] b3 70 [2] ad 6d [2] af 6c [2] b4 6a [2] a8 6d [2] b4 42 }

  condition:
    any of them
}