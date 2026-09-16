rule TTP_XOR_QUAD_CurrentVersionRun_c8e6 {
  strings:
    $key_c8e6 = { 9b 89 [2] bf 87 [2] 94 ab [2] ba 89 [2] ae 92 [2] a1 88 [2] bf 95 [2] bd 94 [2] a6 92 [2] ba 95 [2] a6 ba }

  condition:
    any of them
}