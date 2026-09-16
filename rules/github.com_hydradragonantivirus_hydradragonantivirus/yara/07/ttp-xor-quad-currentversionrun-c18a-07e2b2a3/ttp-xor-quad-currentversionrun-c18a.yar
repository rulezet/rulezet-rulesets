rule TTP_XOR_QUAD_CurrentVersionRun_c18a {
  strings:
    $key_c18a = { 92 e5 [2] b6 eb [2] 9d c7 [2] b3 e5 [2] a7 fe [2] a8 e4 [2] b6 f9 [2] b4 f8 [2] af fe [2] b3 f9 [2] af d6 }

  condition:
    any of them
}