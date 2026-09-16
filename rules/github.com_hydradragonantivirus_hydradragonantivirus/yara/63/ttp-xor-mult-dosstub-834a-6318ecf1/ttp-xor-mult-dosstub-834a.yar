rule TTP_XOR_MULT_DOSStub_834a {
  strings:
    $key_834a = { d7 22 [2] a3 3a [2] e4 38 [2] a3 29 [2] ed 25 [2] e1 2f [2] f6 24 [2] ed 6a [2] d0 }

  condition:
    any of them
}