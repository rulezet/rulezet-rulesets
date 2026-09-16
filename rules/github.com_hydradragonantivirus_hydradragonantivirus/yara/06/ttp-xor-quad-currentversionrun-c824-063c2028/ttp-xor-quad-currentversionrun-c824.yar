rule TTP_XOR_QUAD_CurrentVersionRun_c824 {
  strings:
    $key_c824 = { 9b 4b [2] bf 45 [2] 94 69 [2] ba 4b [2] ae 50 [2] a1 4a [2] bf 57 [2] bd 56 [2] a6 50 [2] ba 57 [2] a6 78 }

  condition:
    any of them
}