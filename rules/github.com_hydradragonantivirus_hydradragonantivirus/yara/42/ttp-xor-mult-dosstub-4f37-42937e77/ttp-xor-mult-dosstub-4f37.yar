rule TTP_XOR_MULT_DOSStub_4f37 {
  strings:
    $key_4f37 = { 1b 5f [2] 6f 47 [2] 28 45 [2] 6f 54 [2] 21 58 [2] 2d 52 [2] 3a 59 [2] 21 17 [2] 1c }

  condition:
    any of them
}