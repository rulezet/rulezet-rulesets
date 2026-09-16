rule TTP_XOR_QUAD_CurrentVersionRun_cbef {
  strings:
    $key_cbef = { 98 80 [2] bc 8e [2] 97 a2 [2] b9 80 [2] ad 9b [2] a2 81 [2] bc 9c [2] be 9d [2] a5 9b [2] b9 9c [2] a5 b3 }

  condition:
    any of them
}