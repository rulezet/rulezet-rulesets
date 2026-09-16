rule TTP_XOR_QUAD_CurrentVersionRun_cb63 {
  strings:
    $key_cb63 = { 98 0c [2] bc 02 [2] 97 2e [2] b9 0c [2] ad 17 [2] a2 0d [2] bc 10 [2] be 11 [2] a5 17 [2] b9 10 [2] a5 3f }

  condition:
    any of them
}