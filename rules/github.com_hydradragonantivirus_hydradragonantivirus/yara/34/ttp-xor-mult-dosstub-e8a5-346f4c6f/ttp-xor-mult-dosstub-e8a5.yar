rule TTP_XOR_MULT_DOSStub_e8a5 {
  strings:
    $key_e8a5 = { bc cd [2] c8 d5 [2] 8f d7 [2] c8 c6 [2] 86 ca [2] 8a c0 [2] 9d cb [2] 86 85 [2] bb }

  condition:
    any of them
}