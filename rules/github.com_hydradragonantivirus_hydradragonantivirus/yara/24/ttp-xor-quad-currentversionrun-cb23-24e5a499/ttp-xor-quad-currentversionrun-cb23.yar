rule TTP_XOR_QUAD_CurrentVersionRun_cb23 {
  strings:
    $key_cb23 = { 98 4c [2] bc 42 [2] 97 6e [2] b9 4c [2] ad 57 [2] a2 4d [2] bc 50 [2] be 51 [2] a5 57 [2] b9 50 [2] a5 7f }

  condition:
    any of them
}