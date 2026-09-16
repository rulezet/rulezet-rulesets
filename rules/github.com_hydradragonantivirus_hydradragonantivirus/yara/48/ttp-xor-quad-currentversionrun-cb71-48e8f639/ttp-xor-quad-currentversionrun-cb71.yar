rule TTP_XOR_QUAD_CurrentVersionRun_cb71 {
  strings:
    $key_cb71 = { 98 1e [2] bc 10 [2] 97 3c [2] b9 1e [2] ad 05 [2] a2 1f [2] bc 02 [2] be 03 [2] a5 05 [2] b9 02 [2] a5 2d }

  condition:
    any of them
}