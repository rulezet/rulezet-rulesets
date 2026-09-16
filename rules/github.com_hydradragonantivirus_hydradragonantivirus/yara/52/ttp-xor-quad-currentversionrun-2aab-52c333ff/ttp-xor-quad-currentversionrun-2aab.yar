rule TTP_XOR_QUAD_CurrentVersionRun_2aab {
  strings:
    $key_2aab = { 79 c4 [2] 5d ca [2] 76 e6 [2] 58 c4 [2] 4c df [2] 43 c5 [2] 5d d8 [2] 5f d9 [2] 44 df [2] 58 d8 [2] 44 f7 }

  condition:
    any of them
}