rule TTP_XOR_MULT_DOSStub_831a {
  strings:
    $key_831a = { d7 72 [2] a3 6a [2] e4 68 [2] a3 79 [2] ed 75 [2] e1 7f [2] f6 74 [2] ed 3a [2] d0 }

  condition:
    any of them
}