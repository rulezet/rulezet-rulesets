rule TTP_XOR_QUAD_CurrentVersionRun_cefb {
  strings:
    $key_cefb = { 9d 94 [2] b9 9a [2] 92 b6 [2] bc 94 [2] a8 8f [2] a7 95 [2] b9 88 [2] bb 89 [2] a0 8f [2] bc 88 [2] a0 a7 }

  condition:
    any of them
}