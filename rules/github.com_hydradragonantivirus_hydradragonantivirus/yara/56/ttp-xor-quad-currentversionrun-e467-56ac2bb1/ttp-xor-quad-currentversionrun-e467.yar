rule TTP_XOR_QUAD_CurrentVersionRun_e467 {
  strings:
    $key_e467 = { b7 08 [2] 93 06 [2] b8 2a [2] 96 08 [2] 82 13 [2] 8d 09 [2] 93 14 [2] 91 15 [2] 8a 13 [2] 96 14 [2] 8a 3b }

  condition:
    any of them
}