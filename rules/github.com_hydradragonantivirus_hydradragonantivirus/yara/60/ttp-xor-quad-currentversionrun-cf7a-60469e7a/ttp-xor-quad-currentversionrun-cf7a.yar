rule TTP_XOR_QUAD_CurrentVersionRun_cf7a {
  strings:
    $key_cf7a = { 9c 15 [2] b8 1b [2] 93 37 [2] bd 15 [2] a9 0e [2] a6 14 [2] b8 09 [2] ba 08 [2] a1 0e [2] bd 09 [2] a1 26 }

  condition:
    any of them
}