rule TTP_XOR_QUAD_CurrentVersionRun_cb43 {
  strings:
    $key_cb43 = { 98 2c [2] bc 22 [2] 97 0e [2] b9 2c [2] ad 37 [2] a2 2d [2] bc 30 [2] be 31 [2] a5 37 [2] b9 30 [2] a5 1f }

  condition:
    any of them
}