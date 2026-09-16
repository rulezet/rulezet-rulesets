rule TTP_XOR_QUAD_CurrentVersionRun_cb30 {
  strings:
    $key_cb30 = { 98 5f [2] bc 51 [2] 97 7d [2] b9 5f [2] ad 44 [2] a2 5e [2] bc 43 [2] be 42 [2] a5 44 [2] b9 43 [2] a5 6c }

  condition:
    any of them
}