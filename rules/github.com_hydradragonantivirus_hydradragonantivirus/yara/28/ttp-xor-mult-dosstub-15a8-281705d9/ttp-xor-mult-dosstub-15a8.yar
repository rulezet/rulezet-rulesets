rule TTP_XOR_MULT_DOSStub_15a8 {
  strings:
    $key_15a8 = { 41 c0 [2] 35 d8 [2] 72 da [2] 35 cb [2] 7b c7 [2] 77 cd [2] 60 c6 [2] 7b 88 [2] 46 }

  condition:
    any of them
}