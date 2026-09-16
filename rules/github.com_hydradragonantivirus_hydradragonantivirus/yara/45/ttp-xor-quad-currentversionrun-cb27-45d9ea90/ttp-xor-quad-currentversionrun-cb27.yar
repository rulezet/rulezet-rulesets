rule TTP_XOR_QUAD_CurrentVersionRun_cb27 {
  strings:
    $key_cb27 = { 98 48 [2] bc 46 [2] 97 6a [2] b9 48 [2] ad 53 [2] a2 49 [2] bc 54 [2] be 55 [2] a5 53 [2] b9 54 [2] a5 7b }

  condition:
    any of them
}