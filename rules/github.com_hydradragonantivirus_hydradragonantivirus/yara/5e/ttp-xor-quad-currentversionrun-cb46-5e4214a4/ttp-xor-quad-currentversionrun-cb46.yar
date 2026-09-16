rule TTP_XOR_QUAD_CurrentVersionRun_cb46 {
  strings:
    $key_cb46 = { 98 29 [2] bc 27 [2] 97 0b [2] b9 29 [2] ad 32 [2] a2 28 [2] bc 35 [2] be 34 [2] a5 32 [2] b9 35 [2] a5 1a }

  condition:
    any of them
}