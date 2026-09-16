rule TTP_XOR_MULT_DOSStub_91f9 {
  strings:
    $key_91f9 = { c5 91 [2] b1 89 [2] f6 8b [2] b1 9a [2] ff 96 [2] f3 9c [2] e4 97 [2] ff d9 [2] c2 }

  condition:
    any of them
}