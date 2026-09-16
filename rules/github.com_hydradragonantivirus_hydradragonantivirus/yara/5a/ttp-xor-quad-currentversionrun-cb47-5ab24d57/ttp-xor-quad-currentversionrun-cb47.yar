rule TTP_XOR_QUAD_CurrentVersionRun_cb47 {
  strings:
    $key_cb47 = { 98 28 [2] bc 26 [2] 97 0a [2] b9 28 [2] ad 33 [2] a2 29 [2] bc 34 [2] be 35 [2] a5 33 [2] b9 34 [2] a5 1b }

  condition:
    any of them
}