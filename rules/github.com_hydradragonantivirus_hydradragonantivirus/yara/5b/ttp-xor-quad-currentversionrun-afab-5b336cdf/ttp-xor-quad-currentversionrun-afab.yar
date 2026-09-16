rule TTP_XOR_QUAD_CurrentVersionRun_afab {
  strings:
    $key_afab = { fc c4 [2] d8 ca [2] f3 e6 [2] dd c4 [2] c9 df [2] c6 c5 [2] d8 d8 [2] da d9 [2] c1 df [2] dd d8 [2] c1 f7 }

  condition:
    any of them
}