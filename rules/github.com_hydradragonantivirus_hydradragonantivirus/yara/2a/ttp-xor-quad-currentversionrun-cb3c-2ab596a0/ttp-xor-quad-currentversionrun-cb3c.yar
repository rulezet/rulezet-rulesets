rule TTP_XOR_QUAD_CurrentVersionRun_cb3c {
  strings:
    $key_cb3c = { 98 53 [2] bc 5d [2] 97 71 [2] b9 53 [2] ad 48 [2] a2 52 [2] bc 4f [2] be 4e [2] a5 48 [2] b9 4f [2] a5 60 }

  condition:
    any of them
}