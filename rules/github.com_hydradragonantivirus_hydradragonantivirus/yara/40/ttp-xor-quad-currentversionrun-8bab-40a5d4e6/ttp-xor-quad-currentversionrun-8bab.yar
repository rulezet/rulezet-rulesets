rule TTP_XOR_QUAD_CurrentVersionRun_8bab {
  strings:
    $key_8bab = { d8 c4 [2] fc ca [2] d7 e6 [2] f9 c4 [2] ed df [2] e2 c5 [2] fc d8 [2] fe d9 [2] e5 df [2] f9 d8 [2] e5 f7 }

  condition:
    any of them
}