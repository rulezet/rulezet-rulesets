rule TTP_XOR_QUAD_CurrentVersionRun_c83c {
  strings:
    $key_c83c = { 9b 53 [2] bf 5d [2] 94 71 [2] ba 53 [2] ae 48 [2] a1 52 [2] bf 4f [2] bd 4e [2] a6 48 [2] ba 4f [2] a6 60 }

  condition:
    any of them
}