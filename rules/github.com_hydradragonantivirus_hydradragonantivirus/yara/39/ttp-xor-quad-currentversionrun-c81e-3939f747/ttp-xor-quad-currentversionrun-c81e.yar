rule TTP_XOR_QUAD_CurrentVersionRun_c81e {
  strings:
    $key_c81e = { 9b 71 [2] bf 7f [2] 94 53 [2] ba 71 [2] ae 6a [2] a1 70 [2] bf 6d [2] bd 6c [2] a6 6a [2] ba 6d [2] a6 42 }

  condition:
    any of them
}