rule TTP_XOR_QUAD_CurrentVersionRun_cb2e {
  strings:
    $key_cb2e = { 98 41 [2] bc 4f [2] 97 63 [2] b9 41 [2] ad 5a [2] a2 40 [2] bc 5d [2] be 5c [2] a5 5a [2] b9 5d [2] a5 72 }

  condition:
    any of them
}