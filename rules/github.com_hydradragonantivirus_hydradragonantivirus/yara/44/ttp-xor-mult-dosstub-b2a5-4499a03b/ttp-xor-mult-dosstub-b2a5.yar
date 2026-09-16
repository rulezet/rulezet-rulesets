rule TTP_XOR_MULT_DOSStub_b2a5 {
  strings:
    $key_b2a5 = { e6 cd [2] 92 d5 [2] d5 d7 [2] 92 c6 [2] dc ca [2] d0 c0 [2] c7 cb [2] dc 85 [2] e1 }

  condition:
    any of them
}