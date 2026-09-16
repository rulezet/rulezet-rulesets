rule TTP_XOR_QUAD_CurrentVersionRun_c7fc {
  strings:
    $key_c7fc = { 94 93 [2] b0 9d [2] 9b b1 [2] b5 93 [2] a1 88 [2] ae 92 [2] b0 8f [2] b2 8e [2] a9 88 [2] b5 8f [2] a9 a0 }

  condition:
    any of them
}