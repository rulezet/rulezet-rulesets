rule TTP_XOR_QUAD_CurrentVersionRun_cb0c {
  strings:
    $key_cb0c = { 98 63 [2] bc 6d [2] 97 41 [2] b9 63 [2] ad 78 [2] a2 62 [2] bc 7f [2] be 7e [2] a5 78 [2] b9 7f [2] a5 50 }

  condition:
    any of them
}