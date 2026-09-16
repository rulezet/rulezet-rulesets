rule TTP_XOR_QUAD_CurrentVersionRun_c051 {
  strings:
    $key_c051 = { 93 3e [2] b7 30 [2] 9c 1c [2] b2 3e [2] a6 25 [2] a9 3f [2] b7 22 [2] b5 23 [2] ae 25 [2] b2 22 [2] ae 0d }

  condition:
    any of them
}