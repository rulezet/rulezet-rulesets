rule TTP_XOR_MULT_DOSStub_84dc {
  strings:
    $key_84dc = { d0 b4 [2] a4 ac [2] e3 ae [2] a4 bf [2] ea b3 [2] e6 b9 [2] f1 b2 [2] ea fc [2] d7 }

  condition:
    any of them
}