rule TTP_XOR_MULT_DOSStub_91e7 {
  strings:
    $key_91e7 = { c5 8f [2] b1 97 [2] f6 95 [2] b1 84 [2] ff 88 [2] f3 82 [2] e4 89 [2] ff c7 [2] c2 }

  condition:
    any of them
}