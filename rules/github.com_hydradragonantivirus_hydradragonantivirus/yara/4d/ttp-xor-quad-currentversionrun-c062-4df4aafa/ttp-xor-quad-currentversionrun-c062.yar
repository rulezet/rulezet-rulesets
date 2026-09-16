rule TTP_XOR_QUAD_CurrentVersionRun_c062 {
  strings:
    $key_c062 = { 93 0d [2] b7 03 [2] 9c 2f [2] b2 0d [2] a6 16 [2] a9 0c [2] b7 11 [2] b5 10 [2] ae 16 [2] b2 11 [2] ae 3e }

  condition:
    any of them
}