rule TTP_XOR_QUAD_CurrentVersionRun_c835 {
  strings:
    $key_c835 = { 9b 5a [2] bf 54 [2] 94 78 [2] ba 5a [2] ae 41 [2] a1 5b [2] bf 46 [2] bd 47 [2] a6 41 [2] ba 46 [2] a6 69 }

  condition:
    any of them
}