rule TTP_XOR_MULT_DOSStub_9383 {
  strings:
    $key_9383 = { c7 eb [2] b3 f3 [2] f4 f1 [2] b3 e0 [2] fd ec [2] f1 e6 [2] e6 ed [2] fd a3 [2] c0 }

  condition:
    any of them
}