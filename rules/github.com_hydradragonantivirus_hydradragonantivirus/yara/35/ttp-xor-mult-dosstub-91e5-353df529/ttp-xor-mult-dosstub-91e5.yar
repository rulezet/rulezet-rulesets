rule TTP_XOR_MULT_DOSStub_91e5 {
  strings:
    $key_91e5 = { c5 8d [2] b1 95 [2] f6 97 [2] b1 86 [2] ff 8a [2] f3 80 [2] e4 8b [2] ff c5 [2] c2 }

  condition:
    any of them
}