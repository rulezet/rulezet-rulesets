rule TTP_XOR_QUAD_CurrentVersionRun_8dab {
  strings:
    $key_8dab = { de c4 [2] fa ca [2] d1 e6 [2] ff c4 [2] eb df [2] e4 c5 [2] fa d8 [2] f8 d9 [2] e3 df [2] ff d8 [2] e3 f7 }

  condition:
    any of them
}