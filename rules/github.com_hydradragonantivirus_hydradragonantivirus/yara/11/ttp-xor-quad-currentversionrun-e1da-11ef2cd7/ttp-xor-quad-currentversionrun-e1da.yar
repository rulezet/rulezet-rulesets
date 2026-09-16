rule TTP_XOR_QUAD_CurrentVersionRun_e1da {
  strings:
    $key_e1da = { b2 b5 [2] 96 bb [2] bd 97 [2] 93 b5 [2] 87 ae [2] 88 b4 [2] 96 a9 [2] 94 a8 [2] 8f ae [2] 93 a9 [2] 8f 86 }

  condition:
    any of them
}