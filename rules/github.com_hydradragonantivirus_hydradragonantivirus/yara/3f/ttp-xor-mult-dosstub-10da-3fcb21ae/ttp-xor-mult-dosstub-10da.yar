rule TTP_XOR_MULT_DOSStub_10da {
  strings:
    $key_10da = { 44 b2 [2] 30 aa [2] 77 a8 [2] 30 b9 [2] 7e b5 [2] 72 bf [2] 65 b4 [2] 7e fa [2] 43 }

  condition:
    any of them
}