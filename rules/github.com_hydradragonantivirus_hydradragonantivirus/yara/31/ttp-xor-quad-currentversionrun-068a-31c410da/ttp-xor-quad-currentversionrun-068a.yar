rule TTP_XOR_QUAD_CurrentVersionRun_068a {
  strings:
    $key_068a = { 55 e5 [2] 71 eb [2] 5a c7 [2] 74 e5 [2] 60 fe [2] 6f e4 [2] 71 f9 [2] 73 f8 [2] 68 fe [2] 74 f9 [2] 68 d6 }

  condition:
    any of them
}