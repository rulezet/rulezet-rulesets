rule TTP_XOR_MULT_DOSStub_85fe {
  strings:
    $key_85fe = { d1 96 [2] a5 8e [2] e2 8c [2] a5 9d [2] eb 91 [2] e7 9b [2] f0 90 [2] eb de [2] d6 }

  condition:
    any of them
}