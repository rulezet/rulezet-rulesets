rule TTP_XOR_QUAD_CurrentVersionRun_c87f {
  strings:
    $key_c87f = { 9b 10 [2] bf 1e [2] 94 32 [2] ba 10 [2] ae 0b [2] a1 11 [2] bf 0c [2] bd 0d [2] a6 0b [2] ba 0c [2] a6 23 }

  condition:
    any of them
}