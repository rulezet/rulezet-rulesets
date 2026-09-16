rule TTP_XOR_QUAD_CurrentVersionRun_cb64 {
  strings:
    $key_cb64 = { 98 0b [2] bc 05 [2] 97 29 [2] b9 0b [2] ad 10 [2] a2 0a [2] bc 17 [2] be 16 [2] a5 10 [2] b9 17 [2] a5 38 }

  condition:
    any of them
}