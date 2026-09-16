rule TTP_XOR_QUAD_CurrentVersionRun_ca1a {
  strings:
    $key_ca1a = { 99 75 [2] bd 7b [2] 96 57 [2] b8 75 [2] ac 6e [2] a3 74 [2] bd 69 [2] bf 68 [2] a4 6e [2] b8 69 [2] a4 46 }

  condition:
    any of them
}