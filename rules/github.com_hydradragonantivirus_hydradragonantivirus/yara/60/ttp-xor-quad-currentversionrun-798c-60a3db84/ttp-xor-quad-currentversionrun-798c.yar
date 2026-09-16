rule TTP_XOR_QUAD_CurrentVersionRun_798c {
  strings:
    $key_798c = { 2a e3 [2] 0e ed [2] 25 c1 [2] 0b e3 [2] 1f f8 [2] 10 e2 [2] 0e ff [2] 0c fe [2] 17 f8 [2] 0b ff [2] 17 d0 }

  condition:
    any of them
}