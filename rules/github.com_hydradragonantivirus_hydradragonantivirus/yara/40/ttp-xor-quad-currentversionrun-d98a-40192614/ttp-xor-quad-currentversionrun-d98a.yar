rule TTP_XOR_QUAD_CurrentVersionRun_d98a {
  strings:
    $key_d98a = { 8a e5 [2] ae eb [2] 85 c7 [2] ab e5 [2] bf fe [2] b0 e4 [2] ae f9 [2] ac f8 [2] b7 fe [2] ab f9 [2] b7 d6 }

  condition:
    any of them
}