rule TTP_XOR_QUAD_CurrentVersionRun_e1dc {
  strings:
    $key_e1dc = { b2 b3 [2] 96 bd [2] bd 91 [2] 93 b3 [2] 87 a8 [2] 88 b2 [2] 96 af [2] 94 ae [2] 8f a8 [2] 93 af [2] 8f 80 }

  condition:
    any of them
}