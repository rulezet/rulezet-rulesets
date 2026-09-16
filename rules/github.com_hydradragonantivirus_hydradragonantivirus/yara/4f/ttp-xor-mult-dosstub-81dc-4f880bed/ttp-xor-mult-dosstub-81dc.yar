rule TTP_XOR_MULT_DOSStub_81dc {
  strings:
    $key_81dc = { d5 b4 [2] a1 ac [2] e6 ae [2] a1 bf [2] ef b3 [2] e3 b9 [2] f4 b2 [2] ef fc [2] d2 }

  condition:
    any of them
}