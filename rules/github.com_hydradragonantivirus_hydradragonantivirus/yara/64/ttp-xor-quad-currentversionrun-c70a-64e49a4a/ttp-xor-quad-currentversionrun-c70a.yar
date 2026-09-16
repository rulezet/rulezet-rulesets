rule TTP_XOR_QUAD_CurrentVersionRun_c70a {
  strings:
    $key_c70a = { 94 65 [2] b0 6b [2] 9b 47 [2] b5 65 [2] a1 7e [2] ae 64 [2] b0 79 [2] b2 78 [2] a9 7e [2] b5 79 [2] a9 56 }

  condition:
    any of them
}