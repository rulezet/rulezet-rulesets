rule TTP_XOR_QUAD_CurrentVersionRun_9bab {
  strings:
    $key_9bab = { c8 c4 [2] ec ca [2] c7 e6 [2] e9 c4 [2] fd df [2] f2 c5 [2] ec d8 [2] ee d9 [2] f5 df [2] e9 d8 [2] f5 f7 }

  condition:
    any of them
}