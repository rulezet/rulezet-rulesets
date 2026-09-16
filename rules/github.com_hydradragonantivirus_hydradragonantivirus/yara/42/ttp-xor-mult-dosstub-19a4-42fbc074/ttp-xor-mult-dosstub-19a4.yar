rule TTP_XOR_MULT_DOSStub_19a4 {
  strings:
    $key_19a4 = { 4d cc [2] 39 d4 [2] 7e d6 [2] 39 c7 [2] 77 cb [2] 7b c1 [2] 6c ca [2] 77 84 [2] 4a }

  condition:
    any of them
}