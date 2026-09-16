rule TTP_XOR_MULT_DOSStub_c4a5 {
  strings:
    $key_c4a5 = { 90 cd [2] e4 d5 [2] a3 d7 [2] e4 c6 [2] aa ca [2] a6 c0 [2] b1 cb [2] aa 85 [2] 97 }

  condition:
    any of them
}