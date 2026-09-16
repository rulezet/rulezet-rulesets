rule TTP_XOR_MULT_DOSStub_1c35 {
  strings:
    $key_1c35 = { 48 5d [2] 3c 45 [2] 7b 47 [2] 3c 56 [2] 72 5a [2] 7e 50 [2] 69 5b [2] 72 15 [2] 4f }

  condition:
    any of them
}