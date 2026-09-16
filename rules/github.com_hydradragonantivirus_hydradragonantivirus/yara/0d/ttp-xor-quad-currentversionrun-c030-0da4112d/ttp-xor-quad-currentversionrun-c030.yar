rule TTP_XOR_QUAD_CurrentVersionRun_c030 {
  strings:
    $key_c030 = { 93 5f [2] b7 51 [2] 9c 7d [2] b2 5f [2] a6 44 [2] a9 5e [2] b7 43 [2] b5 42 [2] ae 44 [2] b2 43 [2] ae 6c }

  condition:
    any of them
}