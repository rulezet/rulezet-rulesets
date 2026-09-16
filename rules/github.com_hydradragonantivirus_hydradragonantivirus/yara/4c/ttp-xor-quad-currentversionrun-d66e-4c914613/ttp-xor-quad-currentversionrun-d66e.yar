rule TTP_XOR_QUAD_CurrentVersionRun_d66e {
  strings:
    $key_d66e = { 85 01 [2] a1 0f [2] 8a 23 [2] a4 01 [2] b0 1a [2] bf 00 [2] a1 1d [2] a3 1c [2] b8 1a [2] a4 1d [2] b8 32 }

  condition:
    any of them
}