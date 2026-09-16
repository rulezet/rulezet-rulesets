rule TTP_XOR_QUAD_CurrentVersionRun_cbfa {
  strings:
    $key_cbfa = { 98 95 [2] bc 9b [2] 97 b7 [2] b9 95 [2] ad 8e [2] a2 94 [2] bc 89 [2] be 88 [2] a5 8e [2] b9 89 [2] a5 a6 }

  condition:
    any of them
}