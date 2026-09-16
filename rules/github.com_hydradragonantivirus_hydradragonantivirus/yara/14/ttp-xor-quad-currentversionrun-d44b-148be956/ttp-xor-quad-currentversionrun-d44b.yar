rule TTP_XOR_QUAD_CurrentVersionRun_d44b {
  strings:
    $key_d44b = { 87 24 [2] a3 2a [2] 88 06 [2] a6 24 [2] b2 3f [2] bd 25 [2] a3 38 [2] a1 39 [2] ba 3f [2] a6 38 [2] ba 17 }

  condition:
    any of them
}