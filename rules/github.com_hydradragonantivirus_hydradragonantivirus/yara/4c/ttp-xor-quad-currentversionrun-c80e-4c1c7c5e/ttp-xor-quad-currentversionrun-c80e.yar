rule TTP_XOR_QUAD_CurrentVersionRun_c80e {
  strings:
    $key_c80e = { 9b 61 [2] bf 6f [2] 94 43 [2] ba 61 [2] ae 7a [2] a1 60 [2] bf 7d [2] bd 7c [2] a6 7a [2] ba 7d [2] a6 52 }

  condition:
    any of them
}