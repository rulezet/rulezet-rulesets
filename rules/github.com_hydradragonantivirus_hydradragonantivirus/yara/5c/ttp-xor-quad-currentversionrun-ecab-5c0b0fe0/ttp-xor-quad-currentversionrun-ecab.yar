rule TTP_XOR_QUAD_CurrentVersionRun_ecab {
  strings:
    $key_ecab = { bf c4 [2] 9b ca [2] b0 e6 [2] 9e c4 [2] 8a df [2] 85 c5 [2] 9b d8 [2] 99 d9 [2] 82 df [2] 9e d8 [2] 82 f7 }

  condition:
    any of them
}