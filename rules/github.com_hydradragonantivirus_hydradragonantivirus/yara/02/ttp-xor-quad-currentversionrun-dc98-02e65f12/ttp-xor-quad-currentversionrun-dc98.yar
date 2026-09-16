rule TTP_XOR_QUAD_CurrentVersionRun_dc98 {
  strings:
    $key_dc98 = { 8f f7 [2] ab f9 [2] 80 d5 [2] ae f7 [2] ba ec [2] b5 f6 [2] ab eb [2] a9 ea [2] b2 ec [2] ae eb [2] b2 c4 }

  condition:
    any of them
}