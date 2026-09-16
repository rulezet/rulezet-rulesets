rule TTP_XOR_QUAD_CurrentVersionRun_698a {
  strings:
    $key_698a = { 3a e5 [2] 1e eb [2] 35 c7 [2] 1b e5 [2] 0f fe [2] 00 e4 [2] 1e f9 [2] 1c f8 [2] 07 fe [2] 1b f9 [2] 07 d6 }

  condition:
    any of them
}