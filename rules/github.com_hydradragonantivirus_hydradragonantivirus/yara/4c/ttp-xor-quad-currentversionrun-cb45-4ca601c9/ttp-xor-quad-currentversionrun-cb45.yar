rule TTP_XOR_QUAD_CurrentVersionRun_cb45 {
  strings:
    $key_cb45 = { 98 2a [2] bc 24 [2] 97 08 [2] b9 2a [2] ad 31 [2] a2 2b [2] bc 36 [2] be 37 [2] a5 31 [2] b9 36 [2] a5 19 }

  condition:
    any of them
}