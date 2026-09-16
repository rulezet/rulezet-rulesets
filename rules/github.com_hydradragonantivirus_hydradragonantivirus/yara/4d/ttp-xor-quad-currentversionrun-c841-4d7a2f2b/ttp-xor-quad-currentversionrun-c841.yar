rule TTP_XOR_QUAD_CurrentVersionRun_c841 {
  strings:
    $key_c841 = { 9b 2e [2] bf 20 [2] 94 0c [2] ba 2e [2] ae 35 [2] a1 2f [2] bf 32 [2] bd 33 [2] a6 35 [2] ba 32 [2] a6 1d }

  condition:
    any of them
}