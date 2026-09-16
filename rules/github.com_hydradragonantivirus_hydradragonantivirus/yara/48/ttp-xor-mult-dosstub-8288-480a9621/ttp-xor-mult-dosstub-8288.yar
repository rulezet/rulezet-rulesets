rule TTP_XOR_MULT_DOSStub_8288 {
  strings:
    $key_8288 = { d6 e0 [2] a2 f8 [2] e5 fa [2] a2 eb [2] ec e7 [2] e0 ed [2] f7 e6 [2] ec a8 [2] d1 }

  condition:
    any of them
}