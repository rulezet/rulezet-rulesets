rule TTP_XOR_QUAD_CurrentVersionRun_f98d {
  strings:
    $key_f98d = { aa e2 [2] 8e ec [2] a5 c0 [2] 8b e2 [2] 9f f9 [2] 90 e3 [2] 8e fe [2] 8c ff [2] 97 f9 [2] 8b fe [2] 97 d1 }

  condition:
    any of them
}