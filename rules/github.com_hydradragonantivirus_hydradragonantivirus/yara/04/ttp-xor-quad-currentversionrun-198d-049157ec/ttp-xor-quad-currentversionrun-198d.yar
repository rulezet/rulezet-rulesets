rule TTP_XOR_QUAD_CurrentVersionRun_198d {
  strings:
    $key_198d = { 4a e2 [2] 6e ec [2] 45 c0 [2] 6b e2 [2] 7f f9 [2] 70 e3 [2] 6e fe [2] 6c ff [2] 77 f9 [2] 6b fe [2] 77 d1 }

  condition:
    any of them
}