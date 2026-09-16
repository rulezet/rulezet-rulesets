rule TTP_XOR_QUAD_CurrentVersionRun_188a {
  strings:
    $key_188a = { 4b e5 [2] 6f eb [2] 44 c7 [2] 6a e5 [2] 7e fe [2] 71 e4 [2] 6f f9 [2] 6d f8 [2] 76 fe [2] 6a f9 [2] 76 d6 }

  condition:
    any of them
}