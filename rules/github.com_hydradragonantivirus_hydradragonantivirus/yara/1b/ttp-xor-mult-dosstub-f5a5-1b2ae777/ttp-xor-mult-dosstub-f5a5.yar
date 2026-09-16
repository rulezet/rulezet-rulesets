rule TTP_XOR_MULT_DOSStub_f5a5 {
  strings:
    $key_f5a5 = { a1 cd [2] d5 d5 [2] 92 d7 [2] d5 c6 [2] 9b ca [2] 97 c0 [2] 80 cb [2] 9b 85 [2] a6 }

  condition:
    any of them
}