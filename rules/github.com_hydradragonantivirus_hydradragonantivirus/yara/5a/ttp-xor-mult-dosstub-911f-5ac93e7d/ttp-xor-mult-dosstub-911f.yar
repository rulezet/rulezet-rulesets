rule TTP_XOR_MULT_DOSStub_911f {
  strings:
    $key_911f = { c5 77 [2] b1 6f [2] f6 6d [2] b1 7c [2] ff 70 [2] f3 7a [2] e4 71 [2] ff 3f [2] c2 }

  condition:
    any of them
}