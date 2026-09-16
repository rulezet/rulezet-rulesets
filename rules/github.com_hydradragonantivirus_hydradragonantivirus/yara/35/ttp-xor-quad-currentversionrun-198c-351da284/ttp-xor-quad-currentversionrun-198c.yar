rule TTP_XOR_QUAD_CurrentVersionRun_198c {
  strings:
    $key_198c = { 4a e3 [2] 6e ed [2] 45 c1 [2] 6b e3 [2] 7f f8 [2] 70 e2 [2] 6e ff [2] 6c fe [2] 77 f8 [2] 6b ff [2] 77 d0 }

  condition:
    any of them
}