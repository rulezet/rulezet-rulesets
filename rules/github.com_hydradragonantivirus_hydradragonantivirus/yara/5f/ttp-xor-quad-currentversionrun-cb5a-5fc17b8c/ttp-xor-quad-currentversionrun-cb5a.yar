rule TTP_XOR_QUAD_CurrentVersionRun_cb5a {
  strings:
    $key_cb5a = { 98 35 [2] bc 3b [2] 97 17 [2] b9 35 [2] ad 2e [2] a2 34 [2] bc 29 [2] be 28 [2] a5 2e [2] b9 29 [2] a5 06 }

  condition:
    any of them
}