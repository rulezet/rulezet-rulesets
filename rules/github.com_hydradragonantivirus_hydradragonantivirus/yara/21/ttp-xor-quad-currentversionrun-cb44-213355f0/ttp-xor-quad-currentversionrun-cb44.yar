rule TTP_XOR_QUAD_CurrentVersionRun_cb44 {
  strings:
    $key_cb44 = { 98 2b [2] bc 25 [2] 97 09 [2] b9 2b [2] ad 30 [2] a2 2a [2] bc 37 [2] be 36 [2] a5 30 [2] b9 37 [2] a5 18 }

  condition:
    any of them
}