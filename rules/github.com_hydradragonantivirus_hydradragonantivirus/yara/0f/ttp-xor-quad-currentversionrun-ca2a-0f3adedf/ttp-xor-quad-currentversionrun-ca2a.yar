rule TTP_XOR_QUAD_CurrentVersionRun_ca2a {
  strings:
    $key_ca2a = { 99 45 [2] bd 4b [2] 96 67 [2] b8 45 [2] ac 5e [2] a3 44 [2] bd 59 [2] bf 58 [2] a4 5e [2] b8 59 [2] a4 76 }

  condition:
    any of them
}