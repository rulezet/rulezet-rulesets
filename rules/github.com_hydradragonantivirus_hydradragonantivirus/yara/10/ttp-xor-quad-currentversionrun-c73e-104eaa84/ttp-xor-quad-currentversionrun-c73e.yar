rule TTP_XOR_QUAD_CurrentVersionRun_c73e {
  strings:
    $key_c73e = { 94 51 [2] b0 5f [2] 9b 73 [2] b5 51 [2] a1 4a [2] ae 50 [2] b0 4d [2] b2 4c [2] a9 4a [2] b5 4d [2] a9 62 }

  condition:
    any of them
}