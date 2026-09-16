rule TTP_XOR_QUAD_CurrentVersionRun_c17d {
  strings:
    $key_c17d = { 92 12 [2] b6 1c [2] 9d 30 [2] b3 12 [2] a7 09 [2] a8 13 [2] b6 0e [2] b4 0f [2] af 09 [2] b3 0e [2] af 21 }

  condition:
    any of them
}