rule TTP_XOR_MULT_DOSStub_2dd9 {
  strings:
    $key_2dd9 = { 79 b1 [2] 0d a9 [2] 4a ab [2] 0d ba [2] 43 b6 [2] 4f bc [2] 58 b7 [2] 43 f9 [2] 7e }

  condition:
    any of them
}