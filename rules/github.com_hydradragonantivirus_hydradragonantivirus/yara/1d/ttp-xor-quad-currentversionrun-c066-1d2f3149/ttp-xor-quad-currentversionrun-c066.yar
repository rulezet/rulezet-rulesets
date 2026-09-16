rule TTP_XOR_QUAD_CurrentVersionRun_c066 {
  strings:
    $key_c066 = { 93 09 [2] b7 07 [2] 9c 2b [2] b2 09 [2] a6 12 [2] a9 08 [2] b7 15 [2] b5 14 [2] ae 12 [2] b2 15 [2] ae 3a }

  condition:
    any of them
}