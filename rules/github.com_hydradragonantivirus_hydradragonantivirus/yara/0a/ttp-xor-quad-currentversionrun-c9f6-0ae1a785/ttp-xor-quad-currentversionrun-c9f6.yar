rule TTP_XOR_QUAD_CurrentVersionRun_c9f6 {
  strings:
    $key_c9f6 = { 9a 99 [2] be 97 [2] 95 bb [2] bb 99 [2] af 82 [2] a0 98 [2] be 85 [2] bc 84 [2] a7 82 [2] bb 85 [2] a7 aa }

  condition:
    any of them
}