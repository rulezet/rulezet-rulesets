rule TTP_XOR_MULT_DOSStub_940a {
  strings:
    $key_940a = { c0 62 [2] b4 7a [2] f3 78 [2] b4 69 [2] fa 65 [2] f6 6f [2] e1 64 [2] fa 2a [2] c7 }

  condition:
    any of them
}