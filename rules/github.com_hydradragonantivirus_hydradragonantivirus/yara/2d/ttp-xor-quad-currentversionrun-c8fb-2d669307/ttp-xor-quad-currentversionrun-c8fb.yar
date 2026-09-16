rule TTP_XOR_QUAD_CurrentVersionRun_c8fb {
  strings:
    $key_c8fb = { 9b 94 [2] bf 9a [2] 94 b6 [2] ba 94 [2] ae 8f [2] a1 95 [2] bf 88 [2] bd 89 [2] a6 8f [2] ba 88 [2] a6 a7 }

  condition:
    any of them
}