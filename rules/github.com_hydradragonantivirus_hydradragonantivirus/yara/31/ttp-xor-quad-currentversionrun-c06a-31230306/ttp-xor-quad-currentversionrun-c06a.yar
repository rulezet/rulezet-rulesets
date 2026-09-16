rule TTP_XOR_QUAD_CurrentVersionRun_c06a {
  strings:
    $key_c06a = { 93 05 [2] b7 0b [2] 9c 27 [2] b2 05 [2] a6 1e [2] a9 04 [2] b7 19 [2] b5 18 [2] ae 1e [2] b2 19 [2] ae 36 }

  condition:
    any of them
}