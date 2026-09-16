rule TTP_XOR_QUAD_CurrentVersionRun_c814 {
  strings:
    $key_c814 = { 9b 7b [2] bf 75 [2] 94 59 [2] ba 7b [2] ae 60 [2] a1 7a [2] bf 67 [2] bd 66 [2] a6 60 [2] ba 67 [2] a6 48 }

  condition:
    any of them
}