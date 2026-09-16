rule TTP_XOR_QUAD_CurrentVersionRun_cb70 {
  strings:
    $key_cb70 = { 98 1f [2] bc 11 [2] 97 3d [2] b9 1f [2] ad 04 [2] a2 1e [2] bc 03 [2] be 02 [2] a5 04 [2] b9 03 [2] a5 2c }

  condition:
    any of them
}