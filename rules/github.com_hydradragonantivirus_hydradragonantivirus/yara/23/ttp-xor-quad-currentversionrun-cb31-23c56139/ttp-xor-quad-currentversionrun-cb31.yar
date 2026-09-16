rule TTP_XOR_QUAD_CurrentVersionRun_cb31 {
  strings:
    $key_cb31 = { 98 5e [2] bc 50 [2] 97 7c [2] b9 5e [2] ad 45 [2] a2 5f [2] bc 42 [2] be 43 [2] a5 45 [2] b9 42 [2] a5 6d }

  condition:
    any of them
}