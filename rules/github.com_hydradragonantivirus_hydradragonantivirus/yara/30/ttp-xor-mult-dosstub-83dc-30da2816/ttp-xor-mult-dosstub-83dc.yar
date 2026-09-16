rule TTP_XOR_MULT_DOSStub_83dc {
  strings:
    $key_83dc = { d7 b4 [2] a3 ac [2] e4 ae [2] a3 bf [2] ed b3 [2] e1 b9 [2] f6 b2 [2] ed fc [2] d0 }

  condition:
    any of them
}