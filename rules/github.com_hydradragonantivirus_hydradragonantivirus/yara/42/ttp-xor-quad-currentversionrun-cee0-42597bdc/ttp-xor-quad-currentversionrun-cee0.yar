rule TTP_XOR_QUAD_CurrentVersionRun_cee0 {
  strings:
    $key_cee0 = { 9d 8f [2] b9 81 [2] 92 ad [2] bc 8f [2] a8 94 [2] a7 8e [2] b9 93 [2] bb 92 [2] a0 94 [2] bc 93 [2] a0 bc }

  condition:
    any of them
}