rule TTP_XOR_QUAD_CurrentVersionRun_da7f {
  strings:
    $key_da7f = { 89 10 [2] ad 1e [2] 86 32 [2] a8 10 [2] bc 0b [2] b3 11 [2] ad 0c [2] af 0d [2] b4 0b [2] a8 0c [2] b4 23 }

  condition:
    any of them
}