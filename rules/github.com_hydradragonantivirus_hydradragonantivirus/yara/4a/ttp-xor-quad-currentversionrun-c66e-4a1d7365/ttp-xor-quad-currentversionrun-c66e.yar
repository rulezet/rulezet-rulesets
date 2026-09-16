rule TTP_XOR_QUAD_CurrentVersionRun_c66e {
  strings:
    $key_c66e = { 95 01 [2] b1 0f [2] 9a 23 [2] b4 01 [2] a0 1a [2] af 00 [2] b1 1d [2] b3 1c [2] a8 1a [2] b4 1d [2] a8 32 }

  condition:
    any of them
}