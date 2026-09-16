rule TTP_XOR_MULT_DOSStub_ddb9 {
  strings:
    $key_ddb9 = { 89 d1 [2] fd c9 [2] ba cb [2] fd da [2] b3 d6 [2] bf dc [2] a8 d7 [2] b3 99 [2] 8e }

  condition:
    any of them
}