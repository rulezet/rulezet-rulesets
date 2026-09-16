rule TTP_XOR_QUAD_CurrentVersionRun_c821 {
  strings:
    $key_c821 = { 9b 4e [2] bf 40 [2] 94 6c [2] ba 4e [2] ae 55 [2] a1 4f [2] bf 52 [2] bd 53 [2] a6 55 [2] ba 52 [2] a6 7d }

  condition:
    any of them
}