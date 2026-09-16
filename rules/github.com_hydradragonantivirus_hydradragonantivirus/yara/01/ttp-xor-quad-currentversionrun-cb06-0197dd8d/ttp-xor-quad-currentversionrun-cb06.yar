rule TTP_XOR_QUAD_CurrentVersionRun_cb06 {
  strings:
    $key_cb06 = { 98 69 [2] bc 67 [2] 97 4b [2] b9 69 [2] ad 72 [2] a2 68 [2] bc 75 [2] be 74 [2] a5 72 [2] b9 75 [2] a5 5a }

  condition:
    any of them
}