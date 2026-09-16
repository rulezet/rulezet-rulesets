rule TTP_XOR_QUAD_CurrentVersionRun_cb58 {
  strings:
    $key_cb58 = { 98 37 [2] bc 39 [2] 97 15 [2] b9 37 [2] ad 2c [2] a2 36 [2] bc 2b [2] be 2a [2] a5 2c [2] b9 2b [2] a5 04 }

  condition:
    any of them
}