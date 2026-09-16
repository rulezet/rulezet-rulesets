rule TTP_XOR_QUAD_CurrentVersionRun_c77c {
  strings:
    $key_c77c = { 94 13 [2] b0 1d [2] 9b 31 [2] b5 13 [2] a1 08 [2] ae 12 [2] b0 0f [2] b2 0e [2] a9 08 [2] b5 0f [2] a9 20 }

  condition:
    any of them
}