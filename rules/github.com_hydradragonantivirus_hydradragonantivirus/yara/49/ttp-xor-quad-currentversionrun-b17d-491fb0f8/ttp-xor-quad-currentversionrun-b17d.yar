rule TTP_XOR_QUAD_CurrentVersionRun_b17d {
  strings:
    $key_b17d = { e2 12 [2] c6 1c [2] ed 30 [2] c3 12 [2] d7 09 [2] d8 13 [2] c6 0e [2] c4 0f [2] df 09 [2] c3 0e [2] df 21 }

  condition:
    any of them
}