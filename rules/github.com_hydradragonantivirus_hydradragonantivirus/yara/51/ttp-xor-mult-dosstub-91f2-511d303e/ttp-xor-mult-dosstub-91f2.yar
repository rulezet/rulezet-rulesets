rule TTP_XOR_MULT_DOSStub_91f2 {
  strings:
    $key_91f2 = { c5 9a [2] b1 82 [2] f6 80 [2] b1 91 [2] ff 9d [2] f3 97 [2] e4 9c [2] ff d2 [2] c2 }

  condition:
    any of them
}