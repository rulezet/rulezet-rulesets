rule TTP_XOR_MULT_DOSStub_821a {
  strings:
    $key_821a = { d6 72 [2] a2 6a [2] e5 68 [2] a2 79 [2] ec 75 [2] e0 7f [2] f7 74 [2] ec 3a [2] d1 }

  condition:
    any of them
}