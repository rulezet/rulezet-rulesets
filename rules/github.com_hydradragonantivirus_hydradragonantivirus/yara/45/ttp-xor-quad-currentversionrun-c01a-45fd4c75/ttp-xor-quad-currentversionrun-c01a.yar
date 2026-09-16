rule TTP_XOR_QUAD_CurrentVersionRun_c01a {
  strings:
    $key_c01a = { 93 75 [2] b7 7b [2] 9c 57 [2] b2 75 [2] a6 6e [2] a9 74 [2] b7 69 [2] b5 68 [2] ae 6e [2] b2 69 [2] ae 46 }

  condition:
    any of them
}