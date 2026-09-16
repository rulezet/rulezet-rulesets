rule TTP_XOR_QUAD_CurrentVersionRun_cb48 {
  strings:
    $key_cb48 = { 98 27 [2] bc 29 [2] 97 05 [2] b9 27 [2] ad 3c [2] a2 26 [2] bc 3b [2] be 3a [2] a5 3c [2] b9 3b [2] a5 14 }

  condition:
    any of them
}