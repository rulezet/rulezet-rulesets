rule TTP_XOR_QUAD_CurrentVersionRun_cb25 {
  strings:
    $key_cb25 = { 98 4a [2] bc 44 [2] 97 68 [2] b9 4a [2] ad 51 [2] a2 4b [2] bc 56 [2] be 57 [2] a5 51 [2] b9 56 [2] a5 79 }

  condition:
    any of them
}