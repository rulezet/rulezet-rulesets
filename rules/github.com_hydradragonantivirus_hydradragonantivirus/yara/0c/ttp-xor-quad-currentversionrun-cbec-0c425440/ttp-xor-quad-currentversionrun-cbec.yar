rule TTP_XOR_QUAD_CurrentVersionRun_cbec {
  strings:
    $key_cbec = { 98 83 [2] bc 8d [2] 97 a1 [2] b9 83 [2] ad 98 [2] a2 82 [2] bc 9f [2] be 9e [2] a5 98 [2] b9 9f [2] a5 b0 }

  condition:
    any of them
}