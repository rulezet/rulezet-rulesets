rule TTP_XOR_QUAD_CurrentVersionRun_c020 {
  strings:
    $key_c020 = { 93 4f [2] b7 41 [2] 9c 6d [2] b2 4f [2] a6 54 [2] a9 4e [2] b7 53 [2] b5 52 [2] ae 54 [2] b2 53 [2] ae 7c }

  condition:
    any of them
}