rule TTP_XOR_QUAD_CurrentVersionRun_cbfc {
  strings:
    $key_cbfc = { 98 93 [2] bc 9d [2] 97 b1 [2] b9 93 [2] ad 88 [2] a2 92 [2] bc 8f [2] be 8e [2] a5 88 [2] b9 8f [2] a5 a0 }

  condition:
    any of them
}