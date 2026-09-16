rule TTP_XOR_QUAD_CurrentVersionRun_cef1 {
  strings:
    $key_cef1 = { 9d 9e [2] b9 90 [2] 92 bc [2] bc 9e [2] a8 85 [2] a7 9f [2] b9 82 [2] bb 83 [2] a0 85 [2] bc 82 [2] a0 ad }

  condition:
    any of them
}