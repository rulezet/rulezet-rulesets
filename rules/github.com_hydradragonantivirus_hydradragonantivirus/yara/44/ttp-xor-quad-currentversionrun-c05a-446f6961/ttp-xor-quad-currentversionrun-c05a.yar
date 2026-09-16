rule TTP_XOR_QUAD_CurrentVersionRun_c05a {
  strings:
    $key_c05a = { 93 35 [2] b7 3b [2] 9c 17 [2] b2 35 [2] a6 2e [2] a9 34 [2] b7 29 [2] b5 28 [2] ae 2e [2] b2 29 [2] ae 06 }

  condition:
    any of them
}