rule TTP_XOR_QUAD_CurrentVersionRun_c9fc {
  strings:
    $key_c9fc = { 9a 93 [2] be 9d [2] 95 b1 [2] bb 93 [2] af 88 [2] a0 92 [2] be 8f [2] bc 8e [2] a7 88 [2] bb 8f [2] a7 a0 }

  condition:
    any of them
}