rule TTP_XOR_QUAD_CurrentVersionRun_cb57 {
  strings:
    $key_cb57 = { 98 38 [2] bc 36 [2] 97 1a [2] b9 38 [2] ad 23 [2] a2 39 [2] bc 24 [2] be 25 [2] a5 23 [2] b9 24 [2] a5 0b }

  condition:
    any of them
}