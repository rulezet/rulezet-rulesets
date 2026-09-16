rule TTP_XOR_QUAD_CurrentVersionRun_cb79 {
  strings:
    $key_cb79 = { 98 16 [2] bc 18 [2] 97 34 [2] b9 16 [2] ad 0d [2] a2 17 [2] bc 0a [2] be 0b [2] a5 0d [2] b9 0a [2] a5 25 }

  condition:
    any of them
}