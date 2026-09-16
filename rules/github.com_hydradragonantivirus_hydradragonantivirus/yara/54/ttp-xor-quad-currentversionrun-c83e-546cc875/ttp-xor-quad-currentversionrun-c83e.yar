rule TTP_XOR_QUAD_CurrentVersionRun_c83e {
  strings:
    $key_c83e = { 9b 51 [2] bf 5f [2] 94 73 [2] ba 51 [2] ae 4a [2] a1 50 [2] bf 4d [2] bd 4c [2] a6 4a [2] ba 4d [2] a6 62 }

  condition:
    any of them
}