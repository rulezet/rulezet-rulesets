rule TTP_XOR_QUAD_CurrentVersionRun_cb2d {
  strings:
    $key_cb2d = { 98 42 [2] bc 4c [2] 97 60 [2] b9 42 [2] ad 59 [2] a2 43 [2] bc 5e [2] be 5f [2] a5 59 [2] b9 5e [2] a5 71 }

  condition:
    any of them
}