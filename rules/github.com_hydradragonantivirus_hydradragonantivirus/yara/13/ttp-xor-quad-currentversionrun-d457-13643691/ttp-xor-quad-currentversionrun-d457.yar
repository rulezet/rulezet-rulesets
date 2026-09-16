rule TTP_XOR_QUAD_CurrentVersionRun_d457 {
  strings:
    $key_d457 = { 87 38 [2] a3 36 [2] 88 1a [2] a6 38 [2] b2 23 [2] bd 39 [2] a3 24 [2] a1 25 [2] ba 23 [2] a6 24 [2] ba 0b }

  condition:
    any of them
}