rule TTP_XOR_QUAD_CurrentVersionRun_e17d {
  strings:
    $key_e17d = { b2 12 [2] 96 1c [2] bd 30 [2] 93 12 [2] 87 09 [2] 88 13 [2] 96 0e [2] 94 0f [2] 8f 09 [2] 93 0e [2] 8f 21 }

  condition:
    any of them
}