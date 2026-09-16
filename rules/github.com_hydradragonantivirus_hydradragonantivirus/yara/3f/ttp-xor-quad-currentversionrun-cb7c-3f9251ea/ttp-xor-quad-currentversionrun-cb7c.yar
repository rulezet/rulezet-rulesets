rule TTP_XOR_QUAD_CurrentVersionRun_cb7c {
  strings:
    $key_cb7c = { 98 13 [2] bc 1d [2] 97 31 [2] b9 13 [2] ad 08 [2] a2 12 [2] bc 0f [2] be 0e [2] a5 08 [2] b9 0f [2] a5 20 }

  condition:
    any of them
}