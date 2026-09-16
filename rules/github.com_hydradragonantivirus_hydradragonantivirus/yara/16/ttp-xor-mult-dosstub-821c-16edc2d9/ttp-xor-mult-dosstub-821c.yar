rule TTP_XOR_MULT_DOSStub_821c {
  strings:
    $key_821c = { d6 74 [2] a2 6c [2] e5 6e [2] a2 7f [2] ec 73 [2] e0 79 [2] f7 72 [2] ec 3c [2] d1 }

  condition:
    any of them
}