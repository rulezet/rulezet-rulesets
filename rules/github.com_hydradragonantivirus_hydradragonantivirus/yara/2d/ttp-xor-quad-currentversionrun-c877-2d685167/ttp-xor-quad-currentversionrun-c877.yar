rule TTP_XOR_QUAD_CurrentVersionRun_c877 {
  strings:
    $key_c877 = { 9b 18 [2] bf 16 [2] 94 3a [2] ba 18 [2] ae 03 [2] a1 19 [2] bf 04 [2] bd 05 [2] a6 03 [2] ba 04 [2] a6 2b }

  condition:
    any of them
}