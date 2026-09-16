rule TTP_XOR_MULT_DOSStub_e4da {
  strings:
    $key_e4da = { b0 b2 [2] c4 aa [2] 83 a8 [2] c4 b9 [2] 8a b5 [2] 86 bf [2] 91 b4 [2] 8a fa [2] b7 }

  condition:
    any of them
}