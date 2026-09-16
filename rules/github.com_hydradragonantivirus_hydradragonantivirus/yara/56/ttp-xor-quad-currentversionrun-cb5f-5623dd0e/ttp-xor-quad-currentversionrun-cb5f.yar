rule TTP_XOR_QUAD_CurrentVersionRun_cb5f {
  strings:
    $key_cb5f = { 98 30 [2] bc 3e [2] 97 12 [2] b9 30 [2] ad 2b [2] a2 31 [2] bc 2c [2] be 2d [2] a5 2b [2] b9 2c [2] a5 03 }

  condition:
    any of them
}