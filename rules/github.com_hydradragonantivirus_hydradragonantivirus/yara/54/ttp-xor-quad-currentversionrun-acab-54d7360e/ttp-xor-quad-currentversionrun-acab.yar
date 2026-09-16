rule TTP_XOR_QUAD_CurrentVersionRun_acab {
  strings:
    $key_acab = { ff c4 [2] db ca [2] f0 e6 [2] de c4 [2] ca df [2] c5 c5 [2] db d8 [2] d9 d9 [2] c2 df [2] de d8 [2] c2 f7 }

  condition:
    any of them
}