rule TTP_XOR_QUAD_CurrentVersionRun_cb09 {
  strings:
    $key_cb09 = { 98 66 [2] bc 68 [2] 97 44 [2] b9 66 [2] ad 7d [2] a2 67 [2] bc 7a [2] be 7b [2] a5 7d [2] b9 7a [2] a5 55 }

  condition:
    any of them
}