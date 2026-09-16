rule TTP_XOR_QUAD_CurrentVersionRun_5d8a {
  strings:
    $key_5d8a = { 0e e5 [2] 2a eb [2] 01 c7 [2] 2f e5 [2] 3b fe [2] 34 e4 [2] 2a f9 [2] 28 f8 [2] 33 fe [2] 2f f9 [2] 33 d6 }

  condition:
    any of them
}