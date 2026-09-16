rule TTP_XOR_MULT_DOSStub_91ee {
  strings:
    $key_91ee = { c5 86 [2] b1 9e [2] f6 9c [2] b1 8d [2] ff 81 [2] f3 8b [2] e4 80 [2] ff ce [2] c2 }

  condition:
    any of them
}