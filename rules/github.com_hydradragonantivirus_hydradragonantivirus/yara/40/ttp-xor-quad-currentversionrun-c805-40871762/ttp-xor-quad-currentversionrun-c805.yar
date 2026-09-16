rule TTP_XOR_QUAD_CurrentVersionRun_c805 {
  strings:
    $key_c805 = { 9b 6a [2] bf 64 [2] 94 48 [2] ba 6a [2] ae 71 [2] a1 6b [2] bf 76 [2] bd 77 [2] a6 71 [2] ba 76 [2] a6 59 }

  condition:
    any of them
}