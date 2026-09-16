rule TTP_XOR_QUAD_CurrentVersionRun_c83f {
  strings:
    $key_c83f = { 9b 50 [2] bf 5e [2] 94 72 [2] ba 50 [2] ae 4b [2] a1 51 [2] bf 4c [2] bd 4d [2] a6 4b [2] ba 4c [2] a6 63 }

  condition:
    any of them
}