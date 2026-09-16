rule TTP_XOR_QUAD_CurrentVersionRun_ca7d {
  strings:
    $key_ca7d = { 99 12 [2] bd 1c [2] 96 30 [2] b8 12 [2] ac 09 [2] a3 13 [2] bd 0e [2] bf 0f [2] a4 09 [2] b8 0e [2] a4 21 }

  condition:
    any of them
}