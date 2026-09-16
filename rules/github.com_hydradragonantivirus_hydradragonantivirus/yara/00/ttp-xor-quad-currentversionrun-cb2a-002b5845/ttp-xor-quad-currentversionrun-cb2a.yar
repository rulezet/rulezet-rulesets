rule TTP_XOR_QUAD_CurrentVersionRun_cb2a {
  strings:
    $key_cb2a = { 98 45 [2] bc 4b [2] 97 67 [2] b9 45 [2] ad 5e [2] a2 44 [2] bc 59 [2] be 58 [2] a5 5e [2] b9 59 [2] a5 76 }

  condition:
    any of them
}