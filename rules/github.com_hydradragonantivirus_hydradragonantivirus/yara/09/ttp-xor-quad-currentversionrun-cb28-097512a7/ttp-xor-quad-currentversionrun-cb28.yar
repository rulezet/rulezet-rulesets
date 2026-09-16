rule TTP_XOR_QUAD_CurrentVersionRun_cb28 {
  strings:
    $key_cb28 = { 98 47 [2] bc 49 [2] 97 65 [2] b9 47 [2] ad 5c [2] a2 46 [2] bc 5b [2] be 5a [2] a5 5c [2] b9 5b [2] a5 74 }

  condition:
    any of them
}