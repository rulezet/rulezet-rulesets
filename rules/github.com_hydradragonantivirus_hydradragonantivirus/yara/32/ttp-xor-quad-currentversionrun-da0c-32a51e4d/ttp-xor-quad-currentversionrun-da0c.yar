rule TTP_XOR_QUAD_CurrentVersionRun_da0c {
  strings:
    $key_da0c = { 89 63 [2] ad 6d [2] 86 41 [2] a8 63 [2] bc 78 [2] b3 62 [2] ad 7f [2] af 7e [2] b4 78 [2] a8 7f [2] b4 50 }

  condition:
    any of them
}