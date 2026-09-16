rule TTP_XOR_MULT_DOSStub_56a5 {
  strings:
    $key_56a5 = { 02 cd [2] 76 d5 [2] 31 d7 [2] 76 c6 [2] 38 ca [2] 34 c0 [2] 23 cb [2] 38 85 [2] 05 }

  condition:
    any of them
}