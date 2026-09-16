rule TTP_XOR_QUAD_CurrentVersionRun_c81b {
  strings:
    $key_c81b = { 9b 74 [2] bf 7a [2] 94 56 [2] ba 74 [2] ae 6f [2] a1 75 [2] bf 68 [2] bd 69 [2] a6 6f [2] ba 68 [2] a6 47 }

  condition:
    any of them
}