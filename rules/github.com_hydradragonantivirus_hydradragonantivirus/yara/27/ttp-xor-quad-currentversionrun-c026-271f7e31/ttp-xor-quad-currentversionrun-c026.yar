rule TTP_XOR_QUAD_CurrentVersionRun_c026 {
  strings:
    $key_c026 = { 93 49 [2] b7 47 [2] 9c 6b [2] b2 49 [2] a6 52 [2] a9 48 [2] b7 55 [2] b5 54 [2] ae 52 [2] b2 55 [2] ae 7a }

  condition:
    any of them
}