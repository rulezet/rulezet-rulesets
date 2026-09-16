rule TTP_XOR_QUAD_CurrentVersionRun_cb62 {
  strings:
    $key_cb62 = { 98 0d [2] bc 03 [2] 97 2f [2] b9 0d [2] ad 16 [2] a2 0c [2] bc 11 [2] be 10 [2] a5 16 [2] b9 11 [2] a5 3e }

  condition:
    any of them
}