rule TTP_XOR_QUAD_CurrentVersionRun_dc84 {
  strings:
    $key_dc84 = { 8f eb [2] ab e5 [2] 80 c9 [2] ae eb [2] ba f0 [2] b5 ea [2] ab f7 [2] a9 f6 [2] b2 f0 [2] ae f7 [2] b2 d8 }

  condition:
    any of them
}