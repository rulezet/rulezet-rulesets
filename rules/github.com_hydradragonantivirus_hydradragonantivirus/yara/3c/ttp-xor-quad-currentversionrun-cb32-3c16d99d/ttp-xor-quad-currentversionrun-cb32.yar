rule TTP_XOR_QUAD_CurrentVersionRun_cb32 {
  strings:
    $key_cb32 = { 98 5d [2] bc 53 [2] 97 7f [2] b9 5d [2] ad 46 [2] a2 5c [2] bc 41 [2] be 40 [2] a5 46 [2] b9 41 [2] a5 6e }

  condition:
    any of them
}