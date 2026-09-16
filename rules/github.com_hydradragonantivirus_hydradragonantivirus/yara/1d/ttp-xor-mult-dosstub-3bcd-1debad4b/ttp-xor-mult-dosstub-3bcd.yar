rule TTP_XOR_MULT_DOSStub_3bcd {
  strings:
    $key_3bcd = { 6f a5 [2] 1b bd [2] 5c bf [2] 1b ae [2] 55 a2 [2] 59 a8 [2] 4e a3 [2] 55 ed [2] 68 }

  condition:
    any of them
}