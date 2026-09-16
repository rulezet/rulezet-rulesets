rule TTP_XOR_QUAD_CurrentVersionRun_cb7e {
  strings:
    $key_cb7e = { 98 11 [2] bc 1f [2] 97 33 [2] b9 11 [2] ad 0a [2] a2 10 [2] bc 0d [2] be 0c [2] a5 0a [2] b9 0d [2] a5 22 }

  condition:
    any of them
}