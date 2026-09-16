rule TTP_XOR_QUAD_CurrentVersionRun_cb49 {
  strings:
    $key_cb49 = { 98 26 [2] bc 28 [2] 97 04 [2] b9 26 [2] ad 3d [2] a2 27 [2] bc 3a [2] be 3b [2] a5 3d [2] b9 3a [2] a5 15 }

  condition:
    any of them
}