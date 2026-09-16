rule TTP_XOR_QUAD_CurrentVersionRun_cb5d {
  strings:
    $key_cb5d = { 98 32 [2] bc 3c [2] 97 10 [2] b9 32 [2] ad 29 [2] a2 33 [2] bc 2e [2] be 2f [2] a5 29 [2] b9 2e [2] a5 01 }

  condition:
    any of them
}