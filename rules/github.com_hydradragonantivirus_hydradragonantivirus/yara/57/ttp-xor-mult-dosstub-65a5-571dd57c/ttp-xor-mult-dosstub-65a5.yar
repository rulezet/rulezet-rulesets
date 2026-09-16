rule TTP_XOR_MULT_DOSStub_65a5 {
  strings:
    $key_65a5 = { 31 cd [2] 45 d5 [2] 02 d7 [2] 45 c6 [2] 0b ca [2] 07 c0 [2] 10 cb [2] 0b 85 [2] 36 }

  condition:
    any of them
}