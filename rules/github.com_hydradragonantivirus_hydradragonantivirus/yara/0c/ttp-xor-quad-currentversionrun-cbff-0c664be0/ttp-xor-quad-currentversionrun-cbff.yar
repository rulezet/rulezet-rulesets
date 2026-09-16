rule TTP_XOR_QUAD_CurrentVersionRun_cbff {
  strings:
    $key_cbff = { 98 90 [2] bc 9e [2] 97 b2 [2] b9 90 [2] ad 8b [2] a2 91 [2] bc 8c [2] be 8d [2] a5 8b [2] b9 8c [2] a5 a3 }

  condition:
    any of them
}