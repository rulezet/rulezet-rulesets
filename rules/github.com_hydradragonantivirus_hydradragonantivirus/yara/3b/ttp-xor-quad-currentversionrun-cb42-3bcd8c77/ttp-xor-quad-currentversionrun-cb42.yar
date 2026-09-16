rule TTP_XOR_QUAD_CurrentVersionRun_cb42 {
  strings:
    $key_cb42 = { 98 2d [2] bc 23 [2] 97 0f [2] b9 2d [2] ad 36 [2] a2 2c [2] bc 31 [2] be 30 [2] a5 36 [2] b9 31 [2] a5 1e }

  condition:
    any of them
}