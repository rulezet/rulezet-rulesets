rule TTP_XOR_QUAD_CurrentVersionRun_568a {
  strings:
    $key_568a = { 05 e5 [2] 21 eb [2] 0a c7 [2] 24 e5 [2] 30 fe [2] 3f e4 [2] 21 f9 [2] 23 f8 [2] 38 fe [2] 24 f9 [2] 38 d6 }

  condition:
    any of them
}