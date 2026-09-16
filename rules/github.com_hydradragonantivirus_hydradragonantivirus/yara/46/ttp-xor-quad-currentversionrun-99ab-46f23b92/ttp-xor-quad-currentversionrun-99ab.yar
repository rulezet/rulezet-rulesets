rule TTP_XOR_QUAD_CurrentVersionRun_99ab {
  strings:
    $key_99ab = { ca c4 [2] ee ca [2] c5 e6 [2] eb c4 [2] ff df [2] f0 c5 [2] ee d8 [2] ec d9 [2] f7 df [2] eb d8 [2] f7 f7 }

  condition:
    any of them
}