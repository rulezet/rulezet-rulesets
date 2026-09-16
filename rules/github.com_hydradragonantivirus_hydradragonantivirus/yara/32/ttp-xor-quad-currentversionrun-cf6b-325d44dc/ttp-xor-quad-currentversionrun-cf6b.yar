rule TTP_XOR_QUAD_CurrentVersionRun_cf6b {
  strings:
    $key_cf6b = { 9c 04 [2] b8 0a [2] 93 26 [2] bd 04 [2] a9 1f [2] a6 05 [2] b8 18 [2] ba 19 [2] a1 1f [2] bd 18 [2] a1 37 }

  condition:
    any of them
}