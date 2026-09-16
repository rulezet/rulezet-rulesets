rule TTP_XOR_QUAD_CurrentVersionRun_ceed {
  strings:
    $key_ceed = { 9d 82 [2] b9 8c [2] 92 a0 [2] bc 82 [2] a8 99 [2] a7 83 [2] b9 9e [2] bb 9f [2] a0 99 [2] bc 9e [2] a0 b1 }

  condition:
    any of them
}