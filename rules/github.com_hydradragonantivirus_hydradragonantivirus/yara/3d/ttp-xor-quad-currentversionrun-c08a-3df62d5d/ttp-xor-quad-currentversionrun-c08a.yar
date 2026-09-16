rule TTP_XOR_QUAD_CurrentVersionRun_c08a {
  strings:
    $key_c08a = { 93 e5 [2] b7 eb [2] 9c c7 [2] b2 e5 [2] a6 fe [2] a9 e4 [2] b7 f9 [2] b5 f8 [2] ae fe [2] b2 f9 [2] ae d6 }

  condition:
    any of them
}