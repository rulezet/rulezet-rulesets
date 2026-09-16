rule TTP_XOR_QUAD_CurrentVersionRun_cbed {
  strings:
    $key_cbed = { 98 82 [2] bc 8c [2] 97 a0 [2] b9 82 [2] ad 99 [2] a2 83 [2] bc 9e [2] be 9f [2] a5 99 [2] b9 9e [2] a5 b1 }

  condition:
    any of them
}