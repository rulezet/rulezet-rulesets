rule TTP_XOR_QUAD_CurrentVersionRun_098d {
  strings:
    $key_098d = { 5a e2 [2] 7e ec [2] 55 c0 [2] 7b e2 [2] 6f f9 [2] 60 e3 [2] 7e fe [2] 7c ff [2] 67 f9 [2] 7b fe [2] 67 d1 }

  condition:
    any of them
}