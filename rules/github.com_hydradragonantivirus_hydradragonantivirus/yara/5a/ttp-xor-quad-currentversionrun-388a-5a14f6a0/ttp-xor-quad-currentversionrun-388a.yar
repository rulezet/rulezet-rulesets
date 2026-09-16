rule TTP_XOR_QUAD_CurrentVersionRun_388a {
  strings:
    $key_388a = { 6b e5 [2] 4f eb [2] 64 c7 [2] 4a e5 [2] 5e fe [2] 51 e4 [2] 4f f9 [2] 4d f8 [2] 56 fe [2] 4a f9 [2] 56 d6 }

  condition:
    any of them
}