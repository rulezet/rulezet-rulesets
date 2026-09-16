rule TTP_XOR_QUAD_CurrentVersionRun_c07d {
  strings:
    $key_c07d = { 93 12 [2] b7 1c [2] 9c 30 [2] b2 12 [2] a6 09 [2] a9 13 [2] b7 0e [2] b5 0f [2] ae 09 [2] b2 0e [2] ae 21 }

  condition:
    any of them
}