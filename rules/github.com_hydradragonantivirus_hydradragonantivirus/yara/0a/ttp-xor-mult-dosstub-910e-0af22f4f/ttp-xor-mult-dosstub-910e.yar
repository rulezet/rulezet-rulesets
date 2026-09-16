rule TTP_XOR_MULT_DOSStub_910e {
  strings:
    $key_910e = { c5 66 [2] b1 7e [2] f6 7c [2] b1 6d [2] ff 61 [2] f3 6b [2] e4 60 [2] ff 2e [2] c2 }

  condition:
    any of them
}