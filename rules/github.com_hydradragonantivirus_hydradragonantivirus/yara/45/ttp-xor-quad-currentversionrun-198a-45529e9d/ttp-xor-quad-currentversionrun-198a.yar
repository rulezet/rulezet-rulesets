rule TTP_XOR_QUAD_CurrentVersionRun_198a {
  strings:
    $key_198a = { 4a e5 [2] 6e eb [2] 45 c7 [2] 6b e5 [2] 7f fe [2] 70 e4 [2] 6e f9 [2] 6c f8 [2] 77 fe [2] 6b f9 [2] 77 d6 }

  condition:
    any of them
}