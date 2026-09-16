rule TTP_XOR_QUAD_CurrentVersionRun_ca2b {
  strings:
    $key_ca2b = { 99 44 [2] bd 4a [2] 96 66 [2] b8 44 [2] ac 5f [2] a3 45 [2] bd 58 [2] bf 59 [2] a4 5f [2] b8 58 [2] a4 77 }

  condition:
    any of them
}