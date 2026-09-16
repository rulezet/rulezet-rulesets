rule TTP_XOR_QUAD_CurrentVersionRun_88ac {
  strings:
    $key_88ac = { db c3 [2] ff cd [2] d4 e1 [2] fa c3 [2] ee d8 [2] e1 c2 [2] ff df [2] fd de [2] e6 d8 [2] fa df [2] e6 f0 }

  condition:
    any of them
}