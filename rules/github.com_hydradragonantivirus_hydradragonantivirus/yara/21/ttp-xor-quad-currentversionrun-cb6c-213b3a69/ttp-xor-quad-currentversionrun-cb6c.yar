rule TTP_XOR_QUAD_CurrentVersionRun_cb6c {
  strings:
    $key_cb6c = { 98 03 [2] bc 0d [2] 97 21 [2] b9 03 [2] ad 18 [2] a2 02 [2] bc 1f [2] be 1e [2] a5 18 [2] b9 1f [2] a5 30 }

  condition:
    any of them
}