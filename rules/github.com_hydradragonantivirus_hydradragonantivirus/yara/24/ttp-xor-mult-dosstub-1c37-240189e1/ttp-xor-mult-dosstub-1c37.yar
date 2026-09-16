rule TTP_XOR_MULT_DOSStub_1c37 {
  strings:
    $key_1c37 = { 48 5f [2] 3c 47 [2] 7b 45 [2] 3c 54 [2] 72 58 [2] 7e 52 [2] 69 59 [2] 72 17 [2] 4f }

  condition:
    any of them
}