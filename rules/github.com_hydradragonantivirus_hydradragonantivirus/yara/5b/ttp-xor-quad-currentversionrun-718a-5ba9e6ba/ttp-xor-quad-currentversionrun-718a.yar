rule TTP_XOR_QUAD_CurrentVersionRun_718a {
  strings:
    $key_718a = { 22 e5 [2] 06 eb [2] 2d c7 [2] 03 e5 [2] 17 fe [2] 18 e4 [2] 06 f9 [2] 04 f8 [2] 1f fe [2] 03 f9 [2] 1f d6 }

  condition:
    any of them
}