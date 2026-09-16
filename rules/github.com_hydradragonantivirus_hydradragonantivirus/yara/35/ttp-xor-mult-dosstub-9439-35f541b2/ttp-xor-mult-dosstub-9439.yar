rule TTP_XOR_MULT_DOSStub_9439 {
  strings:
    $key_9439 = { c0 51 [2] b4 49 [2] f3 4b [2] b4 5a [2] fa 56 [2] f6 5c [2] e1 57 [2] fa 19 [2] c7 }

  condition:
    any of them
}