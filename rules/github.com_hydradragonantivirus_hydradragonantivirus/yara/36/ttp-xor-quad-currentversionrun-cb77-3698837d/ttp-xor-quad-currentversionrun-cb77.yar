rule TTP_XOR_QUAD_CurrentVersionRun_cb77 {
  strings:
    $key_cb77 = { 98 18 [2] bc 16 [2] 97 3a [2] b9 18 [2] ad 03 [2] a2 19 [2] bc 04 [2] be 05 [2] a5 03 [2] b9 04 [2] a5 2b }

  condition:
    any of them
}