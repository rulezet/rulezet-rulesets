rule TTP_XOR_QUAD_CurrentVersionRun_c7f6 {
  strings:
    $key_c7f6 = { 94 99 [2] b0 97 [2] 9b bb [2] b5 99 [2] a1 82 [2] ae 98 [2] b0 85 [2] b2 84 [2] a9 82 [2] b5 85 [2] a9 aa }

  condition:
    any of them
}