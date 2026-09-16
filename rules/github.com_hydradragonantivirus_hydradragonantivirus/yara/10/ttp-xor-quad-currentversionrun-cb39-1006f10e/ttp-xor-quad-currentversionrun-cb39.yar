rule TTP_XOR_QUAD_CurrentVersionRun_cb39 {
  strings:
    $key_cb39 = { 98 56 [2] bc 58 [2] 97 74 [2] b9 56 [2] ad 4d [2] a2 57 [2] bc 4a [2] be 4b [2] a5 4d [2] b9 4a [2] a5 65 }

  condition:
    any of them
}