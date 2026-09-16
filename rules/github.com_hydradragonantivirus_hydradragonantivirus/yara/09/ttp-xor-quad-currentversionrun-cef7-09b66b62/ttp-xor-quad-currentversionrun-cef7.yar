rule TTP_XOR_QUAD_CurrentVersionRun_cef7 {
  strings:
    $key_cef7 = { 9d 98 [2] b9 96 [2] 92 ba [2] bc 98 [2] a8 83 [2] a7 99 [2] b9 84 [2] bb 85 [2] a0 83 [2] bc 84 [2] a0 ab }

  condition:
    any of them
}