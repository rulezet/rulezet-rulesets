rule TTP_XOR_MULT_DOSStub_19b7 {
  strings:
    $key_19b7 = { 4d df [2] 39 c7 [2] 7e c5 [2] 39 d4 [2] 77 d8 [2] 7b d2 [2] 6c d9 [2] 77 97 [2] 4a }

  condition:
    any of them
}