rule TTP_XOR_QUAD_CurrentVersionRun_c034 {
  strings:
    $key_c034 = { 93 5b [2] b7 55 [2] 9c 79 [2] b2 5b [2] a6 40 [2] a9 5a [2] b7 47 [2] b5 46 [2] ae 40 [2] b2 47 [2] ae 68 }

  condition:
    any of them
}