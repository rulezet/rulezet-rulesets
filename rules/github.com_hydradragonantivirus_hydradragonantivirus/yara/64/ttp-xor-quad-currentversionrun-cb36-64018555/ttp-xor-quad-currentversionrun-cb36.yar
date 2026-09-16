rule TTP_XOR_QUAD_CurrentVersionRun_cb36 {
  strings:
    $key_cb36 = { 98 59 [2] bc 57 [2] 97 7b [2] b9 59 [2] ad 42 [2] a2 58 [2] bc 45 [2] be 44 [2] a5 42 [2] b9 45 [2] a5 6a }

  condition:
    any of them
}