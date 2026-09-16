rule TTP_XOR_QUAD_CurrentVersionRun_cb01 {
  strings:
    $key_cb01 = { 98 6e [2] bc 60 [2] 97 4c [2] b9 6e [2] ad 75 [2] a2 6f [2] bc 72 [2] be 73 [2] a5 75 [2] b9 72 [2] a5 5d }

  condition:
    any of them
}