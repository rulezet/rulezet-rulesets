rule TTP_XOR_QUAD_CurrentVersionRun_c856 {
  strings:
    $key_c856 = { 9b 39 [2] bf 37 [2] 94 1b [2] ba 39 [2] ae 22 [2] a1 38 [2] bf 25 [2] bd 24 [2] a6 22 [2] ba 25 [2] a6 0a }

  condition:
    any of them
}