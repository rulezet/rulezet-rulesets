rule TTP_XOR_QUAD_CurrentVersionRun_c8e7 {
  strings:
    $key_c8e7 = { 9b 88 [2] bf 86 [2] 94 aa [2] ba 88 [2] ae 93 [2] a1 89 [2] bf 94 [2] bd 95 [2] a6 93 [2] ba 94 [2] a6 bb }

  condition:
    any of them
}