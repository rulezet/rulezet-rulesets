rule TTP_XOR_QUAD_CurrentVersionRun_cef6 {
  strings:
    $key_cef6 = { 9d 99 [2] b9 97 [2] 92 bb [2] bc 99 [2] a8 82 [2] a7 98 [2] b9 85 [2] bb 84 [2] a0 82 [2] bc 85 [2] a0 aa }

  condition:
    any of them
}