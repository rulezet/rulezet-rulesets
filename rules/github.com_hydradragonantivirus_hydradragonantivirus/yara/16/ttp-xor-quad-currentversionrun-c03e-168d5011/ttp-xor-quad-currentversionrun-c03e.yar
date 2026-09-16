rule TTP_XOR_QUAD_CurrentVersionRun_c03e {
  strings:
    $key_c03e = { 93 51 [2] b7 5f [2] 9c 73 [2] b2 51 [2] a6 4a [2] a9 50 [2] b7 4d [2] b5 4c [2] ae 4a [2] b2 4d [2] ae 62 }

  condition:
    any of them
}