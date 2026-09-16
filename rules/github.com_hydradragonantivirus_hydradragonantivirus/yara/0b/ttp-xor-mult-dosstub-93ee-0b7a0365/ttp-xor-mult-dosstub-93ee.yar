rule TTP_XOR_MULT_DOSStub_93ee {
  strings:
    $key_93ee = { c7 86 [2] b3 9e [2] f4 9c [2] b3 8d [2] fd 81 [2] f1 8b [2] e6 80 [2] fd ce [2] c0 }

  condition:
    any of them
}