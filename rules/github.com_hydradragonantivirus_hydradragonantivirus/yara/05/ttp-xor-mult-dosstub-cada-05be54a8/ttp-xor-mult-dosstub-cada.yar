rule TTP_XOR_MULT_DOSStub_cada {
  strings:
    $key_cada = { 9e b2 [2] ea aa [2] ad a8 [2] ea b9 [2] a4 b5 [2] a8 bf [2] bf b4 [2] a4 fa [2] 99 }

  condition:
    any of them
}