rule TTP_XOR_QUAD_CurrentVersionRun_97ab {
  strings:
    $key_97ab = { c4 c4 [2] e0 ca [2] cb e6 [2] e5 c4 [2] f1 df [2] fe c5 [2] e0 d8 [2] e2 d9 [2] f9 df [2] e5 d8 [2] f9 f7 }

  condition:
    any of them
}