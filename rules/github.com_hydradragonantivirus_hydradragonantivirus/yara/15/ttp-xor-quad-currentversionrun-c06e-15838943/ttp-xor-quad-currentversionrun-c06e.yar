rule TTP_XOR_QUAD_CurrentVersionRun_c06e {
  strings:
    $key_c06e = { 93 01 [2] b7 0f [2] 9c 23 [2] b2 01 [2] a6 1a [2] a9 00 [2] b7 1d [2] b5 1c [2] ae 1a [2] b2 1d [2] ae 32 }

  condition:
    any of them
}