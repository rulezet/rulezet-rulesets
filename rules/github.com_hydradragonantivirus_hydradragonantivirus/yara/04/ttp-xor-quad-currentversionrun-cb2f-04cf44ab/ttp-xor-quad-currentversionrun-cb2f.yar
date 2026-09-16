rule TTP_XOR_QUAD_CurrentVersionRun_cb2f {
  strings:
    $key_cb2f = { 98 40 [2] bc 4e [2] 97 62 [2] b9 40 [2] ad 5b [2] a2 41 [2] bc 5c [2] be 5d [2] a5 5b [2] b9 5c [2] a5 73 }

  condition:
    any of them
}