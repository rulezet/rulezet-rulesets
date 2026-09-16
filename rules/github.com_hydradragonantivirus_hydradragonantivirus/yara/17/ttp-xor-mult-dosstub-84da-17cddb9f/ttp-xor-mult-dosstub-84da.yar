rule TTP_XOR_MULT_DOSStub_84da {
  strings:
    $key_84da = { d0 b2 [2] a4 aa [2] e3 a8 [2] a4 b9 [2] ea b5 [2] e6 bf [2] f1 b4 [2] ea fa [2] d7 }

  condition:
    any of them
}