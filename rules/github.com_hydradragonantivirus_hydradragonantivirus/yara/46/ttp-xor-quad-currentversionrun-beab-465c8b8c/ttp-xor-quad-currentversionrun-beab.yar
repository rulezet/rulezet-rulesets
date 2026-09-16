rule TTP_XOR_QUAD_CurrentVersionRun_beab {
  strings:
    $key_beab = { ed c4 [2] c9 ca [2] e2 e6 [2] cc c4 [2] d8 df [2] d7 c5 [2] c9 d8 [2] cb d9 [2] d0 df [2] cc d8 [2] d0 f7 }

  condition:
    any of them
}