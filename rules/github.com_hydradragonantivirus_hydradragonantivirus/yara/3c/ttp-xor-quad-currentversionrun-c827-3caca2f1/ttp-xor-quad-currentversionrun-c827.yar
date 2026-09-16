rule TTP_XOR_QUAD_CurrentVersionRun_c827 {
  strings:
    $key_c827 = { 9b 48 [2] bf 46 [2] 94 6a [2] ba 48 [2] ae 53 [2] a1 49 [2] bf 54 [2] bd 55 [2] a6 53 [2] ba 54 [2] a6 7b }

  condition:
    any of them
}