rule TTP_XOR_QUAD_CurrentVersionRun_cb19 {
  strings:
    $key_cb19 = { 98 76 [2] bc 78 [2] 97 54 [2] b9 76 [2] ad 6d [2] a2 77 [2] bc 6a [2] be 6b [2] a5 6d [2] b9 6a [2] a5 45 }

  condition:
    any of them
}