rule TTP_XOR_QUAD_CurrentVersionRun_dc8a {
  strings:
    $key_dc8a = { 8f e5 [2] ab eb [2] 80 c7 [2] ae e5 [2] ba fe [2] b5 e4 [2] ab f9 [2] a9 f8 [2] b2 fe [2] ae f9 [2] b2 d6 }

  condition:
    any of them
}