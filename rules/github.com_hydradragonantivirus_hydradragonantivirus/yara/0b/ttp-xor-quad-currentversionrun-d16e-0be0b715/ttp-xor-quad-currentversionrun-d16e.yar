rule TTP_XOR_QUAD_CurrentVersionRun_d16e {
  strings:
    $key_d16e = { 82 01 [2] a6 0f [2] 8d 23 [2] a3 01 [2] b7 1a [2] b8 00 [2] a6 1d [2] a4 1c [2] bf 1a [2] a3 1d [2] bf 32 }

  condition:
    any of them
}