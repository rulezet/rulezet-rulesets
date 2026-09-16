rule TTP_XOR_MULT_DOSStub_97fe {
  strings:
    $key_97fe = { c3 96 [2] b7 8e [2] f0 8c [2] b7 9d [2] f9 91 [2] f5 9b [2] e2 90 [2] f9 de [2] c4 }

  condition:
    any of them
}