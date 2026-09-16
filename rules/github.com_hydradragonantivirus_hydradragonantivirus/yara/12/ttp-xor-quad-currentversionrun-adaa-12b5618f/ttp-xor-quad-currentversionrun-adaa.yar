rule TTP_XOR_QUAD_CurrentVersionRun_adaa {
  strings:
    $key_adaa = { fe c5 [2] da cb [2] f1 e7 [2] df c5 [2] cb de [2] c4 c4 [2] da d9 [2] d8 d8 [2] c3 de [2] df d9 [2] c3 f6 }

  condition:
    any of them
}