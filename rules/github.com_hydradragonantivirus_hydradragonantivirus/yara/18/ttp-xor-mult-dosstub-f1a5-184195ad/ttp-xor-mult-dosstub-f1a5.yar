rule TTP_XOR_MULT_DOSStub_f1a5 {
  strings:
    $key_f1a5 = { a5 cd [2] d1 d5 [2] 96 d7 [2] d1 c6 [2] 9f ca [2] 93 c0 [2] 84 cb [2] 9f 85 [2] a2 }

  condition:
    any of them
}