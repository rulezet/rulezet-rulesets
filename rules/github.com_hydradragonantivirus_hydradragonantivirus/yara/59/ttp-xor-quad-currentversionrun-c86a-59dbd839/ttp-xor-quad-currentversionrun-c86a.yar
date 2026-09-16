rule TTP_XOR_QUAD_CurrentVersionRun_c86a {
  strings:
    $key_c86a = { 9b 05 [2] bf 0b [2] 94 27 [2] ba 05 [2] ae 1e [2] a1 04 [2] bf 19 [2] bd 18 [2] a6 1e [2] ba 19 [2] a6 36 }

  condition:
    any of them
}