rule TTP_XOR_QUAD_CurrentVersionRun_cb14 {
  strings:
    $key_cb14 = { 98 7b [2] bc 75 [2] 97 59 [2] b9 7b [2] ad 60 [2] a2 7a [2] bc 67 [2] be 66 [2] a5 60 [2] b9 67 [2] a5 48 }

  condition:
    any of them
}