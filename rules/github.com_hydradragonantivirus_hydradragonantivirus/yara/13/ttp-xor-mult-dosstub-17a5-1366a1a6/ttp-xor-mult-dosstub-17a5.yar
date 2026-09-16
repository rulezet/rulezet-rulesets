rule TTP_XOR_MULT_DOSStub_17a5 {
  strings:
    $key_17a5 = { 43 cd [2] 37 d5 [2] 70 d7 [2] 37 c6 [2] 79 ca [2] 75 c0 [2] 62 cb [2] 79 85 [2] 44 }

  condition:
    any of them
}