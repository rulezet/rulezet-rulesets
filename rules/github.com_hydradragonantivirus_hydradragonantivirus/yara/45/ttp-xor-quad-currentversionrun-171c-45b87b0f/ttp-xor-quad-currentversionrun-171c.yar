rule TTP_XOR_QUAD_CurrentVersionRun_171c {
  strings:
    $key_171c = { 44 73 [2] 60 7d [2] 4b 51 [2] 65 73 [2] 71 68 [2] 7e 72 [2] 60 6f [2] 62 6e [2] 79 68 [2] 65 6f [2] 79 40 }

  condition:
    any of them
}