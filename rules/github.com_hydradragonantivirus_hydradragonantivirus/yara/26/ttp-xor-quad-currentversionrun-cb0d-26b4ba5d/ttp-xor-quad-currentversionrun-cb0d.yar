rule TTP_XOR_QUAD_CurrentVersionRun_cb0d {
  strings:
    $key_cb0d = { 98 62 [2] bc 6c [2] 97 40 [2] b9 62 [2] ad 79 [2] a2 63 [2] bc 7e [2] be 7f [2] a5 79 [2] b9 7e [2] a5 51 }

  condition:
    any of them
}