rule TTP_XOR_QUAD_CurrentVersionRun_c031 {
  strings:
    $key_c031 = { 93 5e [2] b7 50 [2] 9c 7c [2] b2 5e [2] a6 45 [2] a9 5f [2] b7 42 [2] b5 43 [2] ae 45 [2] b2 42 [2] ae 6d }

  condition:
    any of them
}