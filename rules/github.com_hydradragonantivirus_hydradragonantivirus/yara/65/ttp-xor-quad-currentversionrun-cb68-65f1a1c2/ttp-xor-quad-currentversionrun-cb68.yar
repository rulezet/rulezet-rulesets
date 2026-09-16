rule TTP_XOR_QUAD_CurrentVersionRun_cb68 {
  strings:
    $key_cb68 = { 98 07 [2] bc 09 [2] 97 25 [2] b9 07 [2] ad 1c [2] a2 06 [2] bc 1b [2] be 1a [2] a5 1c [2] b9 1b [2] a5 34 }

  condition:
    any of them
}