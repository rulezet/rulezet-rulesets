rule TTP_XOR_QUAD_CurrentVersionRun_cb5e {
  strings:
    $key_cb5e = { 98 31 [2] bc 3f [2] 97 13 [2] b9 31 [2] ad 2a [2] a2 30 [2] bc 2d [2] be 2c [2] a5 2a [2] b9 2d [2] a5 02 }

  condition:
    any of them
}