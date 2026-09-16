rule TTP_XOR_QUAD_CurrentVersionRun_db8a {
  strings:
    $key_db8a = { 88 e5 [2] ac eb [2] 87 c7 [2] a9 e5 [2] bd fe [2] b2 e4 [2] ac f9 [2] ae f8 [2] b5 fe [2] a9 f9 [2] b5 d6 }

  condition:
    any of them
}