rule TTP_XOR_QUAD_CurrentVersionRun_cb6d {
  strings:
    $key_cb6d = { 98 02 [2] bc 0c [2] 97 20 [2] b9 02 [2] ad 19 [2] a2 03 [2] bc 1e [2] be 1f [2] a5 19 [2] b9 1e [2] a5 31 }

  condition:
    any of them
}