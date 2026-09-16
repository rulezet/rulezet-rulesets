rule TTP_XOR_QUAD_CurrentVersionRun_cb1d {
  strings:
    $key_cb1d = { 98 72 [2] bc 7c [2] 97 50 [2] b9 72 [2] ad 69 [2] a2 73 [2] bc 6e [2] be 6f [2] a5 69 [2] b9 6e [2] a5 41 }

  condition:
    any of them
}