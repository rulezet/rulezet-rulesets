rule TTP_XOR_QUAD_CurrentVersionRun_c86b {
  strings:
    $key_c86b = { 9b 04 [2] bf 0a [2] 94 26 [2] ba 04 [2] ae 1f [2] a1 05 [2] bf 18 [2] bd 19 [2] a6 1f [2] ba 18 [2] a6 37 }

  condition:
    any of them
}