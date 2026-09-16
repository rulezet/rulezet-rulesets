rule TTP_XOR_QUAD_CurrentVersionRun_cb4e {
  strings:
    $key_cb4e = { 98 21 [2] bc 2f [2] 97 03 [2] b9 21 [2] ad 3a [2] a2 20 [2] bc 3d [2] be 3c [2] a5 3a [2] b9 3d [2] a5 12 }

  condition:
    any of them
}