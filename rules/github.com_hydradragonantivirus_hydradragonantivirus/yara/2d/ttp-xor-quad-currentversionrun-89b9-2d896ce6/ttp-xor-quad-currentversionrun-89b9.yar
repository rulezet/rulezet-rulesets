rule TTP_XOR_QUAD_CurrentVersionRun_89b9 {
  strings:
    $key_89b9 = { da d6 [2] fe d8 [2] d5 f4 [2] fb d6 [2] ef cd [2] e0 d7 [2] fe ca [2] fc cb [2] e7 cd [2] fb ca [2] e7 e5 }

  condition:
    any of them
}