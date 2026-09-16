rule TTP_XOR_QUAD_CurrentVersionRun_cb73 {
  strings:
    $key_cb73 = { 98 1c [2] bc 12 [2] 97 3e [2] b9 1c [2] ad 07 [2] a2 1d [2] bc 00 [2] be 01 [2] a5 07 [2] b9 00 [2] a5 2f }

  condition:
    any of them
}