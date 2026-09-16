rule TTP_XOR_QUAD_CurrentVersionRun_cb04 {
  strings:
    $key_cb04 = { 98 6b [2] bc 65 [2] 97 49 [2] b9 6b [2] ad 70 [2] a2 6a [2] bc 77 [2] be 76 [2] a5 70 [2] b9 77 [2] a5 58 }

  condition:
    any of them
}