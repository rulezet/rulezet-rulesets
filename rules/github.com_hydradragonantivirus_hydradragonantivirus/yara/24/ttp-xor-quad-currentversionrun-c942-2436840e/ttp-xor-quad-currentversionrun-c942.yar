rule TTP_XOR_QUAD_CurrentVersionRun_c942 {
  strings:
    $key_c942 = { 9a 2d [2] be 23 [2] 95 0f [2] bb 2d [2] af 36 [2] a0 2c [2] be 31 [2] bc 30 [2] a7 36 [2] bb 31 [2] a7 1e }

  condition:
    any of them
}