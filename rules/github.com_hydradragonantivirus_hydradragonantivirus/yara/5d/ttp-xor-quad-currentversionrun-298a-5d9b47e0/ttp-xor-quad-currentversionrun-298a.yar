rule TTP_XOR_QUAD_CurrentVersionRun_298a {
  strings:
    $key_298a = { 7a e5 [2] 5e eb [2] 75 c7 [2] 5b e5 [2] 4f fe [2] 40 e4 [2] 5e f9 [2] 5c f8 [2] 47 fe [2] 5b f9 [2] 47 d6 }

  condition:
    any of them
}