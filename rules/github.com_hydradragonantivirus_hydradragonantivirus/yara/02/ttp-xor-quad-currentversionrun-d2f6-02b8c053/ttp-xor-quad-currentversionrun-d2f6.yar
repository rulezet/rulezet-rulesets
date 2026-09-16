rule TTP_XOR_QUAD_CurrentVersionRun_d2f6 {
  strings:
    $key_d2f6 = { 81 99 [2] a5 97 [2] 8e bb [2] a0 99 [2] b4 82 [2] bb 98 [2] a5 85 [2] a7 84 [2] bc 82 [2] a0 85 [2] bc aa }

  condition:
    any of them
}