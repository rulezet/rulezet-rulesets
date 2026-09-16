rule TTP_XOR_MULT_DOSStub_938d {
  strings:
    $key_938d = { c7 e5 [2] b3 fd [2] f4 ff [2] b3 ee [2] fd e2 [2] f1 e8 [2] e6 e3 [2] fd ad [2] c0 }

  condition:
    any of them
}