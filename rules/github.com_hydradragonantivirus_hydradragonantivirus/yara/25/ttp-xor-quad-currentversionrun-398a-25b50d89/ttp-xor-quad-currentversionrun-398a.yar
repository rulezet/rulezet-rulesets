rule TTP_XOR_QUAD_CurrentVersionRun_398a {
  strings:
    $key_398a = { 6a e5 [2] 4e eb [2] 65 c7 [2] 4b e5 [2] 5f fe [2] 50 e4 [2] 4e f9 [2] 4c f8 [2] 57 fe [2] 4b f9 [2] 57 d6 }

  condition:
    any of them
}