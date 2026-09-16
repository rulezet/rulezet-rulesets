rule TTP_XOR_QUAD_CurrentVersionRun_698c {
  strings:
    $key_698c = { 3a e3 [2] 1e ed [2] 35 c1 [2] 1b e3 [2] 0f f8 [2] 00 e2 [2] 1e ff [2] 1c fe [2] 07 f8 [2] 1b ff [2] 07 d0 }

  condition:
    any of them
}