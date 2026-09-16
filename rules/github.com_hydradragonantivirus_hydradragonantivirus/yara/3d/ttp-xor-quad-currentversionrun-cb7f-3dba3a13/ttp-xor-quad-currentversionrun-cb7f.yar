rule TTP_XOR_QUAD_CurrentVersionRun_cb7f {
  strings:
    $key_cb7f = { 98 10 [2] bc 1e [2] 97 32 [2] b9 10 [2] ad 0b [2] a2 11 [2] bc 0c [2] be 0d [2] a5 0b [2] b9 0c [2] a5 23 }

  condition:
    any of them
}