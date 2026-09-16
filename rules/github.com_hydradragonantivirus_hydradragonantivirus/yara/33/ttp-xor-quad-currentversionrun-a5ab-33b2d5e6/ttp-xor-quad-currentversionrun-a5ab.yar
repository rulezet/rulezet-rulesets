rule TTP_XOR_QUAD_CurrentVersionRun_a5ab {
  strings:
    $key_a5ab = { f6 c4 [2] d2 ca [2] f9 e6 [2] d7 c4 [2] c3 df [2] cc c5 [2] d2 d8 [2] d0 d9 [2] cb df [2] d7 d8 [2] cb f7 }

  condition:
    any of them
}